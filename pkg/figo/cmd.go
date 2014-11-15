package figo

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v2"
)

// GetConfig loads and returns project configuration.
func GetConfig(cfgPath string) (Options, error) {
	var (
		body []byte
		err  error
	)
	if IsExist(cfgPath) {
		body, err = ioutil.ReadFile(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("fail to read yaml file: %v", err)
		}
	} else {
		log.Printf("Yaml(%s) does not exist locally, try to fetch from web...", cfgPath)
		body, err = HttpGetBytes(&http.Client{}, cfgPath, nil)
		if err != nil {
			return nil, fmt.Errorf("fail to fetch yaml file: %v", err)
		}
	}

	config := make(Options)
	if err = yaml.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	return config, nil
}

// GetClient returns a new Docker client.
func GetClient() (*Client, error) {
	baseUrl := DockerUrl()
	client, err := NewClient(baseUrl)
	if err != nil {
		return nil, fmt.Errorf("fail to create new client: %v", err)
	}
	return client, nil
}

var normalCharPattern = regexp.MustCompile("[a-zA-Z0-9]+")

// GetProjectName returns given project name,
// if it is empty, then guesses it by config file path,
// otherwise, just returns 'defualt'.
func GetProjectName(cfgPath, name string) string {
	name = normalCharPattern.FindString(name)
	if len(name) > 0 {
		return name
	}
	absPath, _ := filepath.Abs(cfgPath)
	name = path.Base(path.Dir(absPath))
	if len(name) > 0 {
		return name
	}
	return "default"
}

// GetProject initializes and returns a new project.
func GetProject(name, cfgPath string) (*Project, error) {
	config, err := GetConfig(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("fail to parse config file: %v", err)
	}
	client, err := GetClient()
	if err != nil {
		return nil, fmt.Errorf("fail to create new client: %v", err)
	}
	return NewProjectFromConfig(GetProjectName(cfgPath, name), config, client)
}

func Setup(proName string, cfgPath string) (*Project, error) {
	return GetProject(proName, cfgPath)
}
