package figo

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
)

type (
	Options map[string]map[string]interface{}

	Link struct {
		*Service
		Name string
	}
	Links   map[string]Link
	Volumes map[string]interface{}

	Service struct {
		name    string
		client  *Client
		project string
		links   Links
		volumes Volumes
		options map[string]interface{}
	}
)

func NewService(
	name string,
	client *Client,
	project string,
	links Links,
	volumes Volumes,
	options map[string]interface{}) *Service {
	return &Service{
		name:    name,
		client:  client,
		project: project,
		links:   links,
		volumes: volumes,
		options: options,
	}
}

func (s *Service) GetLinkedNames() []string {
	links := make([]string, 0, len(s.links))
	for link := range s.links {
		links = append(links, link)
	}
	return links
}

// CanBeBuilt returns true if this is buildable service.
func (s *Service) CanBeBuilt() bool {
	_, ok := s.options["build"]
	return ok
}

// buildTagName returns the tag to give to images built for this service.
func (s *Service) buildTagName() string {
	return s.project + "_" + s.name
}

var imageIdPattern = regexp.MustCompile("Successfully built ([0-9a-f]+)")

func (s *Service) Build(noCache bool) (string, error) {
	log.Printf("Building %s...", s.name)

	dockerfile := path.Join(s.options["build"].(string), "Dockerfile")
	if !IsFile(dockerfile) {
		return "", fmt.Errorf("build dockerfile does not exist or is not a file: %s", dockerfile)
	}

	file, err := os.Open(dockerfile)
	if err != nil {
		return "", fmt.Errorf("fail to open dockerfile: %v", err)
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("fail to read dockerfile: %v", err)
	}
	fi, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("fail to get dockerfile info: %v", err)
	}
	inputbuf := bytes.NewBuffer(nil)
	so := NewStreamOutput()

	tr := tar.NewWriter(inputbuf)
	tr.WriteHeader(&tar.Header{Name: "Dockerfile", Size: int64(len(data)), ModTime: fi.ModTime()})
	tr.Write(data)
	tr.Close()
	opts := BuildImageOptions{
		Name:           s.buildTagName(),
		NoCache:        noCache,
		RmTmpContainer: true,
		InputStream:    inputbuf,
		OutputStream:   so,
		RawJSONStream:  true,
	}
	if err := s.client.BuildImage(opts); err != nil {
		return "", err
	}

	var imageId string
	if len(so.Events) > 0 {
		e := so.Events[len(so.Events)-1]
		m := imageIdPattern.FindAllStringSubmatch(e["stream"], 1)
		if m != nil {
			imageId = m[0][1]
		}
	}

	return imageId, nil
}

// Recreate a container. An intermediate container is created so that
// the new container has the same name, while still supporting
// `volumes-from` the original container.
func (s *Service) RecreateContainer(c *Container, options map[string]string) (*Container, error) {
	if err := c.Stop(); err != nil {
		_, ok1 := err.(*NoSuchContainer)
		_, ok2 := err.(*ContainerNotRunning)
		if !ok1 && !ok2 {
			return nil, fmt.Errorf("fail to stop container(%s): %v", c.Name, err)
		}
	}

	intermediate, err := CreateContainer(s.client, map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("fail to create container(%s): %v", c.Name, err)
	}
	if err = intermediate.Start(); err != nil {
		return nil, fmt.Errorf("fail to start container(%s): %v", c.Name, err)
	}
	if _, err = intermediate.Wait(); err != nil {
		return nil, fmt.Errorf("fail to wait container(%s): %v", c.Name, err)
	}
	// FIXME: container.remove() ???
	// options = dict(override_options)

	container, err := s.CreateContainer(false, options)
	if err != nil {
		return nil, fmt.Errorf("fail to create container(%s): %v", c.Name, err)
	}
	if err = s.StartContainer(container, intermediate, options); err != nil {
		return nil, fmt.Errorf("fail to start container(%s): %v", c.Name, err)
	}

	// intermediate_container.remove() ???

	return container, nil
}

// HasApiContainer returns true if the container was created to fulfill this service.
func (s *Service) HasApiContainer(apiContainer *APIContainers, oneOff bool) bool {
	name := GetApiContainerName(apiContainer)
	if len(name) == 0 || !IsValidContainerName(name, oneOff) {
		return false
	}
	projectName, serviceName, _ := ParseContainerName(name)
	return projectName == s.project && serviceName == s.name
}

// Containers returns a list of containers belong to service.
func (s *Service) Containers(stopped, oneOff bool) ([]*Container, error) {
	apiContainers, err := s.client.ListContainers(ListContainersOptions{All: stopped})
	if err != nil {
		return nil, fmt.Errorf("fail to list containers: %v", err)
	}
	containers := make([]*Container, 0, len(apiContainers))
	for _, apiContainer := range apiContainers {
		if s.HasApiContainer(&apiContainer, oneOff) {
			containers = append(containers, NewContainerFromPs(s.client, &apiContainer))
		}
	}
	return containers, nil
}

func (s *Service) nextContainerNumber(containers []*Container) int {
	max := 0
	for _, c := range containers {
		_, _, num := ParseContainerName(c.Name)
		if num > max {
			max = num
		}
	}
	return max + 1
}

func (s *Service) nextContainerName(containers []*Container, oneOff bool) string {
	bits := []string{s.project, s.name}
	if oneOff {
		bits = append(bits, "run")
	}
	bits = append(bits, ToStr(s.nextContainerNumber(containers)))
	return strings.Join(bits, "_")
}

// If a container for this service doesn't exist, create and start one. If there are
// any, stop them, create+start new ones, and remove the old containers.
func (s *Service) RecreateContainers() ([]*Container, error) {
	containers, err := s.Containers(true, false)
	if err != nil {
		return nil, fmt.Errorf("fail to get containers(%s): %v", s.name, err)
	}

	if len(containers) == 0 {
		log.Printf("Creating %s...", s.nextContainerName(containers, false))
		container, err := s.CreateContainer(false, map[string]string{})
		if err != nil {
			return nil, fmt.Errorf("fail to create container: %v", err)
		}
		if err = s.StartContainer(container, nil, map[string]string{}); err != nil {
			return nil, err
		}
		return []*Container{container}, nil
	}

	tuples := make([]*Container, 0, 10)
	for _, c := range containers {
		log.Printf("Recreating %s...", c.Name)
		container, err := s.RecreateContainer(c, map[string]string{})
		if err != nil {
			return nil, fmt.Errorf("fail to recreate container: %v", err)
		}
		tuples = append(tuples, container)
	}
	return tuples, nil
}

func (s *Service) StartOrCreateContainers() ([]*Container, error) {
	containers, err := s.Containers(true, false)
	if err != nil {
		return nil, fmt.Errorf("fail to get containers(%s): %v", s.name, err)
	}

	if len(containers) == 0 {
		log.Printf("Creating %s...", s.nextContainerName(containers, false))
		container, err := s.CreateContainer(false, map[string]string{})
		if err != nil {
			return nil, fmt.Errorf("fail to create container: %v", err)
		}
		if err = s.StartContainer(container, nil, map[string]string{}); err != nil {
			return nil, err
		}
		return []*Container{container}, nil
	}

	for _, c := range containers {
		err = s.StartContainerIfStopped(c, map[string]string{})
		if err != nil {
			return nil, fmt.Errorf("fail to start container: %v", err)
		}
	}
	return containers, nil
}

var (
	DockerConfigKeys = []string{"image", "command", "hostname", "domainname", "user", "detach", "stdin_open", "tty", "mem_limit", "ports", "environment", "dns", "volumes", "entrypoint", "privileged", "volumes_from", "net", "working_dir"}
)

func (s *Service) getContainerCreateOptions(oneOff bool, options map[string]string) (map[string]interface{}, error) {
	containerOptions := map[string]interface{}{}
	for _, k := range DockerConfigKeys {
		if v, ok := s.options[k]; ok {
			containerOptions[k] = v.(string)
		}
	}
	for k, v := range options {
		containerOptions[k] = v
	}

	containers, err := s.Containers(true, oneOff)
	if err != nil {
		return nil, err
	}
	containerOptions["name"] = s.nextContainerName(containers, oneOff)

	// If a qualified hostname was given, split it into an
	// unqualified hostname and a domainname unless domainname
	// was also given explicitly. This matches the behavior of
	// the official Docker CLI in that scenario.
	if containerOptions["hostname"] != nil &&
		strings.Contains(containerOptions["hostname"].(string), ".") &&
		containerOptions["domainname"] == nil {
		infos := strings.Split(containerOptions["hostname"].(string), ".")
		containerOptions["hostname"] = infos[0]
		containerOptions["domainname"] = infos[2]
	}

	// FIXME: what's the form of 'ports' and 'expose' arguments, space-separate?
	if containerOptions["ports"] != nil ||
		s.options["expose"] != nil {
		oldPorts := []string{}
		if containerOptions["ports"] != nil {
			oldPorts = strings.Split(containerOptions["ports"].(string), " ")
		}
		oldExposes := []string{}
		if s.options["expose"] != nil {
			oldExposes = strings.Split(s.options["ports"].(string), " ")
		}

		ports := make([]interface{}, 0)
		allPorts := append(oldPorts, oldExposes...)
		for _, rawPort := range allPorts {
			var port interface{}
			if strings.Contains(rawPort, ":") {
				infos := strings.Split(rawPort, ":")
				rawPort = infos[len(infos)-1]
				port = rawPort
			}
			if strings.Contains(rawPort, "/") {
				port = strings.Split(rawPort, "/")
			}
			ports = append(ports, port)
		}
		containerOptions["ports"] = ports
	}

	if containerOptions["volumes"] != nil {
		containerOptions["volumes"], err = ParseVolumeSpec(containerOptions["volumes"].(string))
		if err != nil {
			return nil, err
		}
	}

	if containerOptions["environment"] != nil {
		// FIXME: what's the form of 'environment' argument?
		log.Printf("container config option 'environment' not implemented yet")
	}

	if s.CanBeBuilt() {
		apiImages, err := s.client.ListImages(true)
		if err != nil {
			return nil, fmt.Errorf("fail to list images: %v", err)
		}
		tagName := s.buildTagName()
		hasFoundTag := false
	SEARCH_TAG:
		for _, apiImage := range apiImages {
			for _, repoTag := range apiImage.RepoTags {
				if repoTag == tagName {
					hasFoundTag = true
					break SEARCH_TAG
				}
			}
		}
		if !hasFoundTag {
			if _, err = s.Build(false); err != nil {
				return nil, fmt.Errorf("fail to build service: %v", err)
			}
		}
		containerOptions["image"] = tagName
	}

	// Delete options which are only used when starting
	for _, key := range []string{"privileged", "net", "dns"} {
		delete(containerOptions, key)
	}

	return containerOptions, nil
}

// CreateContainer creates a container for this service.
// If the image doesn't exist, attempt to pull it.
func (s *Service) CreateContainer(oneOff bool, options map[string]string) (*Container, error) {
	containerOptions, err := s.getContainerCreateOptions(oneOff, options)
	if err != nil {
		return nil, err
	}
	c, err := CreateContainer(s.client, containerOptions)
	if err != nil {
		if err == ErrNoSuchImage {
			log.Printf("Pulling image %s...", containerOptions["image"])
			if err = s.client.PullImage(PullImageOptions{Repository: containerOptions["image"].(string)},
				AuthConfiguration{}); err != nil {
				return nil, err
			}
			c, err = CreateContainer(s.client, containerOptions)
		}
	}
	return c, err
}

func (s *Service) StartContainerIfStopped(c *Container, options map[string]string) error {
	if c.IsRunning() {
		return nil
	}

	log.Printf("Starting %s...", c.Name)
	return s.StartContainer(c, nil, options)
}

// StartContainer starts a existing container.
func (s *Service) StartContainer(c, intermediate *Container, options map[string]string) (err error) {
	if c == nil {
		c, err = s.CreateContainer(false, options)
		if err != nil {
			return err
		}
	}

	startOptions := map[string]interface{}{}
	for k, v := range s.options {
		startOptions[k] = v
	}
	for k, v := range options {
		startOptions[k] = v
	}

	// FIXME: start container config
	// https://gowalker.org/github.com/fsouza/go-dockerclient#HostConfig
	//  volume_bindings = dict(
	//     build_volume_binding(parse_volume_spec(volume))
	//     for volume in options.get('volumes') or []
	//     if ':' in volume)

	// privileged = options.get('privileged', False)
	// net = options.get('net', 'bridge')
	// dns = options.get('dns', None)

	// container.start(
	//             links=self._get_links(link_to_self=options.get('one_off', False)),
	//             port_bindings=ports,
	//             binds=volume_bindings,
	//             volumes_from=self._get_volumes_from(intermediate_container),
	//             privileged=privileged,
	//             network_mode=net,
	//             dns=dns,
	//         )
	hostConfig := &HostConfig{}
	return s.client.StartContainer(c.ID, hostConfig)
}
