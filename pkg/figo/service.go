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
