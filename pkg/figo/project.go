package figo

import (
	"fmt"
	"log"
	"strings"
)

// Project represents a collection of services.
type Project struct {
	name     string
	services []*Service
	client   *Client
}

// NewProject initializes and returns a minimal project.
func NewProject(name string, services []*Service, client *Client) *Project {
	return &Project{
		name:     name,
		services: services,
		client:   client,
	}
}

func in(slice []interface{}, str string) bool {
	for _, s := range slice {
		if str == strings.Split(s.(string), ":")[0] {
			return true
		}
	}
	return false
}

func visit(dicts, unmarked Options, marked map[string]bool, sorted *[]map[string]interface{}, dict map[string]interface{}) error {
	name := dict["name"].(string)
	if marked[name] {
		if links, ok := dict["links"]; ok && in(links.([]interface{}), name) {
			return fmt.Errorf("a service can not link to itself: %s", name)
		}
		if links, ok := dict["volumes_from"]; ok && in(links.([]interface{}), name) {
			return fmt.Errorf("a service can not mount itself as volume: %s", name)
		}
		return fmt.Errorf("circular import found: %s", name)
	}
	if _, ok := unmarked[name]; ok {
		marked[name] = true
		if links, ok := dict["links"]; ok {
			for _, link := range links.([]interface{}) {
				dict := dicts[strings.Split(link.(string), ":")[0]]
				if dict == nil {
					return fmt.Errorf("link service does not exist: %s", link)
				}
				if err := visit(dicts, unmarked, marked, sorted, dict); err != nil {
					return err
				}
			}
		}
		if links, ok := dict["volumes_from"]; ok {
			for _, link := range links.([]interface{}) {
				dict := dicts[strings.Split(link.(string), ":")[0]]
				if dict == nil {
					continue
				}
				if err := visit(dicts, unmarked, marked, sorted, dict); err != nil {
					return err
				}
			}
		}
		delete(marked, name)
		delete(unmarked, name)

		// FIXME: no fucking idea why Fig starts with first one, should reverse list first in Go
		// since we did Topological sort.
		// *sorted = append((*sorted)[:1], (*sorted)[:]...)
		// (*sorted)[0] = dict
		*sorted = append(*sorted, dict)
	}
	return nil
}

// SortServiceDicts does Topological sort for services.
func SortServiceDicts(dicts Options) ([]map[string]interface{}, error) {
	unmarked := make(Options)
	for k, v := range dicts {
		unmarked[k] = v
	}
	marked := make(map[string]bool)
	sorted := make([]map[string]interface{}, 0, len(dicts))

	for _, dict := range unmarked {
		if err := visit(dicts, unmarked, marked, &sorted, dict); err != nil {
			return nil, fmt.Errorf("fail to sort services: %v", err)
		}
	}
	return sorted, nil
}

// NewProjectFromDicts creates new project from a list of dicts representing services.
func NewProjectFromDicts(name string, dicts Options, client *Client) (*Project, error) {
	pro := NewProject(name, []*Service{}, client)
	sorted, err := SortServiceDicts(dicts)
	if err != nil {
		return nil, err
	}

	// dbgutil.FormatDisplay("sorted", sorted)
	for _, dict := range sorted {
		serviceName := dict["name"].(string)
		links, err := pro.GetLinks(dict)
		if err != nil {
			return nil, err
		}
		volumes, err := pro.GetVolumesFrom(dict)
		if err != nil {
			return nil, err
		}
		pro.services = append(pro.services, NewService(serviceName, client, name, links, volumes, dict))
	}
	return pro, nil
}

// NewProjectFromConfig creates new project from configuration.
func NewProjectFromConfig(name string, config Options, client *Client) (*Project, error) {
	dicts := make(Options)
	for name, service := range config {
		if service == nil {
			return nil, fmt.Errorf("Service \"%s\" doesn't have any configuration options. All top level keys in your yaml must map to a dictionary of configuration options", name)
		}
		service["name"] = name
		dicts[name] = service
	}
	return NewProjectFromDicts(name, dicts, client)
}

type NoSuchService struct {
	Name string
}

func (e NoSuchService) Error() string {
	return fmt.Sprintf("no such service: %s", e.Name)
}

// GetService retrieve a service by name.
// It returns NoSuchService if the named service does not exist.
func (p *Project) GetService(name string) (*Service, error) {
	for _, s := range p.services {
		if s.name == name {
			return s, nil
		}
	}
	return nil, NoSuchService{name}
}

// GetLinks returns links from dict.
func (p *Project) GetLinks(dict map[string]interface{}) (Links, error) {
	links := make(Links)
	var (
		linkStr     string
		serviceName string
		linkName    string
	)
	if _, ok := dict["links"]; ok {
		for _, link := range dict["links"].([]interface{}) {
			linkStr = link.(string)
			if strings.Contains(linkStr, ":") {
				infos := strings.SplitN(linkStr, ":", 2)
				serviceName = infos[0]
				linkName = infos[1]
			} else {
				serviceName = linkStr
			}
			s, err := p.GetService(serviceName)
			if err != nil {
				return nil, fmt.Errorf("Service \"%s\" has a link to service \"%s\" which does not exist.", dict["name"], serviceName)
			}
			links[serviceName] = Link{s, linkName}
		}
		delete(dict, "links")
	}
	return links, nil
}

// GetVolumesFrom returns volumes_from from dict.
func (p *Project) GetVolumesFrom(dict map[string]interface{}) (Volumes, error) {
	volumes := make(Volumes)
	if _, ok := dict["volumes_from"]; ok {
		for _, volume := range dict["volumes_from"].([]interface{}) {
			volumeName := volume.(string)
			service, err := p.GetService(volumeName)
			if err != nil {
				if _, ok := err.(NoSuchService); ok {
					container, err := NewContainerFromId(p.client, volumeName)
					if err != nil {
						return nil, fmt.Errorf("service \"%s\" mounts volumes from \"%s\", which is not the name of a service or container", dict["name"], volumeName)
					}
					volumes[volumeName] = container
				}
				return nil, fmt.Errorf("fail to get service(%s) volume from(%s): %v", dict["name"], volumeName, err)
			}
			volumes[volumeName] = service
		}
		delete(dict, "volumes_from")
	}
	return volumes, nil
}

// ListServicesNames returns a list of services' names.
func (p *Project) ListServicesNames() []string {
	names := make([]string, len(p.services))
	for i, s := range p.services {
		names[i] = s.name
	}
	return names
}

func (p *Project) injectLinks(services []*Service) (_ []*Service, err error) {
	allServices := make([]*Service, 0, len(services))
	for _, s := range services {
		allServices = append(allServices, s)

		var linkedServices []*Service
		linkedNames := s.GetLinkedNames()
		if len(linkedNames) > 0 {
			linkedServices, err = p.GetServices(linkedNames, true)
			if err != nil {
				return nil, err
			}
			allServices = append(allServices, linkedServices...)
		}
	}
	return allServices, nil
}

// GetServices returns a list of this project's services filtered
// by the provided list of entries, or all services if entries is empty or nil.
//
// If includeLinks is true, returns a list including the links for
// entries, in order of dependency.
//
// Preserves the original order of Project.services where possible,
// reordering as needed to resolve links.
//
// It returns NoSuchService if any of the named services do not exist.
// FIXME: may run into infinite loop if project has no service.
func (p *Project) GetServices(entries []string, includeLinks bool) (_ []*Service, err error) {
	// Return all services.
	if entries == nil || len(entries) == 0 {
		return p.GetServices(p.ListServicesNames(), includeLinks)
	}

	unsorted := make([]*Service, len(entries))
	for i, name := range entries {
		s, err := p.GetService(name)
		if err != nil {
			return nil, err
		}
		unsorted[i] = s
	}

	// FIXME: unsorted already contains needed services, why this again?
	// Fig: fig/project.py: Project.get_services
	services := unsorted

	if includeLinks {
		services, err = p.injectLinks(services)
		if err != nil {
			return nil, err
		}
	}

	set := map[string]bool{}
	uniques := make([]*Service, 0, len(services))
	for _, s := range services {
		if !set[s.name] {
			uniques = append(uniques, s)
			set[s.name] = true
		}
	}
	return uniques, nil
}

func (p *Project) Build(entries []string, noCache bool) error {
	services, err := p.GetServices(entries, false)
	if err != nil {
		return err
	}
	for _, s := range services {
		if s.CanBeBuilt() {
			if _, err = s.Build(noCache); err != nil {
				return err
			}
		} else {
			log.Printf("%s uses an image, skipping", s.name)
		}
	}
	return nil
}
