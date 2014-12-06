package figo

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// Port represents the port number and the protocol, in the form
// <number>/<protocol>. For example: 80/tcp.
type Port string

// Port returns the number of the port.
func (p Port) Port() string {
	return strings.Split(string(p), "/")[0]
}

// Proto returns the name of the protocol.
func (p Port) Proto() string {
	parts := strings.Split(string(p), "/")
	if len(parts) == 1 {
		return "tcp"
	}
	return parts[1]
}

func parsePort(rawPort string) (int, error) {
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return 0, err
	}
	return int(port), nil
}

// Config is the list of configuration options used when creating a container.
// Config does not the options that are specific to starting a container on a
// given host.  Those are contained in HostConfig
type Config struct {
	Hostname        string              `json:"Hostname,omitempty" yaml:"Hostname,omitempty"`
	Domainname      string              `json:"Domainname,omitempty" yaml:"Domainname,omitempty"`
	User            string              `json:"User,omitempty" yaml:"User,omitempty"`
	Memory          int64               `json:"Memory,omitempty" yaml:"Memory,omitempty"`
	MemorySwap      int64               `json:"MemorySwap,omitempty" yaml:"MemorySwap,omitempty"`
	CPUShares       int64               `json:"CpuShares,omitempty" yaml:"CpuShares,omitempty"`
	CPUSet          string              `json:"CpuSet,omitempty" yaml:"CpuSet,omitempty"`
	AttachStdin     bool                `json:"AttachStdin,omitempty" yaml:"AttachStdin,omitempty"`
	AttachStdout    bool                `json:"AttachStdout,omitempty" yaml:"AttachStdout,omitempty"`
	AttachStderr    bool                `json:"AttachStderr,omitempty" yaml:"AttachStderr,omitempty"`
	PortSpecs       []string            `json:"PortSpecs,omitempty" yaml:"PortSpecs,omitempty"`
	ExposedPorts    map[Port]struct{}   `json:"ExposedPorts,omitempty" yaml:"ExposedPorts,omitempty"`
	Tty             bool                `json:"Tty,omitempty" yaml:"Tty,omitempty"`
	OpenStdin       bool                `json:"OpenStdin,omitempty" yaml:"OpenStdin,omitempty"`
	StdinOnce       bool                `json:"StdinOnce,omitempty" yaml:"StdinOnce,omitempty"`
	Env             []string            `json:"Env,omitempty" yaml:"Env,omitempty"`
	Cmd             []string            `json:"Cmd,omitempty" yaml:"Cmd,omitempty"`
	DNS             []string            `json:"Dns,omitempty" yaml:"Dns,omitempty"` // For Docker API v1.9 and below only
	Image           string              `json:"Image,omitempty" yaml:"Image,omitempty"`
	Volumes         map[string]struct{} `json:"Volumes,omitempty" yaml:"Volumes,omitempty"`
	VolumesFrom     string              `json:"VolumesFrom,omitempty" yaml:"VolumesFrom,omitempty"`
	WorkingDir      string              `json:"WorkingDir,omitempty" yaml:"WorkingDir,omitempty"`
	Entrypoint      []string            `json:"Entrypoint,omitempty" yaml:"Entrypoint,omitempty"`
	NetworkDisabled bool                `json:"NetworkDisabled,omitempty" yaml:"NetworkDisabled,omitempty"`
}

// State represents the state of a container.
type State struct {
	Running    bool      `json:"Running,omitempty" yaml:"Running,omitempty"`
	Paused     bool      `json:"Paused,omitempty" yaml:"Paused,omitempty"`
	Pid        int       `json:"Pid,omitempty" yaml:"Pid,omitempty"`
	ExitCode   int       `json:"ExitCode,omitempty" yaml:"ExitCode,omitempty"`
	StartedAt  time.Time `json:"StartedAt,omitempty" yaml:"StartedAt,omitempty"`
	FinishedAt time.Time `json:"FinishedAt,omitempty" yaml:"FinishedAt,omitempty"`
}

// String returns the string representation of a state.
func (s *State) String() string {
	if s.Running {
		if s.Paused {
			return "paused"
		}
		return fmt.Sprintf("Up %s", time.Now().UTC().Sub(s.StartedAt))
	}
	return fmt.Sprintf("Exit %d", s.ExitCode)
}

// PortBinding represents the host/container port mapping as returned in the
// `docker inspect` json
type PortBinding struct {
	HostIP   string `json:"HostIP,omitempty" yaml:"HostIP,omitempty"`
	HostPort string `json:"HostPort,omitempty" yaml:"HostPort,omitempty"`
}

// PortMapping represents a deprecated field in the `docker inspect` output,
// and its value as found in NetworkSettings should always be nil
type PortMapping map[string]string

// NetworkSettings contains network-related information about a container
type NetworkSettings struct {
	IPAddress   string                 `json:"IPAddress,omitempty" yaml:"IPAddress,omitempty"`
	IPPrefixLen int                    `json:"IPPrefixLen,omitempty" yaml:"IPPrefixLen,omitempty"`
	Gateway     string                 `json:"Gateway,omitempty" yaml:"Gateway,omitempty"`
	Bridge      string                 `json:"Bridge,omitempty" yaml:"Bridge,omitempty"`
	PortMapping map[string]PortMapping `json:"PortMapping,omitempty" yaml:"PortMapping,omitempty"`
	Ports       map[Port][]PortBinding `json:"Ports,omitempty" yaml:"Ports,omitempty"`
}

// ListContainersOptions specify parameters to the ListContainers function.
//
// See http://goo.gl/XqtcyU for more details.
type ListContainersOptions struct {
	All    bool
	Size   bool
	Limit  int
	Since  string
	Before string
}

// APIPort is a type that represents a port mapping returned by the Docker API
type APIPort struct {
	PrivatePort int64  `json:"PrivatePort,omitempty" yaml:"PrivatePort,omitempty"`
	PublicPort  int64  `json:"PublicPort,omitempty" yaml:"PublicPort,omitempty"`
	Type        string `json:"Type,omitempty" yaml:"Type,omitempty"`
	IP          string `json:"IP,omitempty" yaml:"IP,omitempty"`
}

// APIContainers represents a container.
//
// See http://goo.gl/QeFH7U for more details.
type APIContainers struct {
	ID         string    `json:"Id" yaml:"Id"`
	Image      string    `json:"Image,omitempty" yaml:"Image,omitempty"`
	Command    string    `json:"Command,omitempty" yaml:"Command,omitempty"`
	Created    int64     `json:"Created,omitempty" yaml:"Created,omitempty"`
	Status     string    `json:"Status,omitempty" yaml:"Status,omitempty"`
	Ports      []APIPort `json:"Ports,omitempty" yaml:"Ports,omitempty"`
	SizeRw     int64     `json:"SizeRw,omitempty" yaml:"SizeRw,omitempty"`
	SizeRootFs int64     `json:"SizeRootFs,omitempty" yaml:"SizeRootFs,omitempty"`
	Names      []string  `json:"Names,omitempty" yaml:"Names,omitempty"`
}

// ListContainers returns a slice of containers matching the given criteria.
//
// See http://goo.gl/XqtcyU for more details.
func (c *Client) ListContainers(opts ListContainersOptions) ([]APIContainers, error) {
	path := "/containers/json?" + queryString(opts)
	body, _, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var containers []APIContainers
	err = json.Unmarshal(body, &containers)
	if err != nil {
		return nil, err
	}
	return containers, nil
}

// PortMappingAPI translates the port mappings as contained in NetworkSettings
// into the format in which they would appear when returned by the API
func (settings *NetworkSettings) PortMappingAPI() []APIPort {
	var mapping []APIPort
	for port, bindings := range settings.Ports {
		p, _ := parsePort(port.Port())
		if len(bindings) == 0 {
			mapping = append(mapping, APIPort{
				PublicPort: int64(p),
				Type:       port.Proto(),
			})
			continue
		}
		for _, binding := range bindings {
			p, _ := parsePort(port.Port())
			h, _ := parsePort(binding.HostPort)
			mapping = append(mapping, APIPort{
				PrivatePort: int64(p),
				PublicPort:  int64(h),
				Type:        port.Proto(),
				IP:          binding.HostIP,
			})
		}
	}
	return mapping
}

// KeyValuePair is a type for generic key/value pairs as used in the Lxc
// configuration
type KeyValuePair struct {
	Key   string `json:"Key,omitempty" yaml:"Key,omitempty"`
	Value string `json:"Value,omitempty" yaml:"Value,omitempty"`
}

// RestartPolicy represents the policy for automatically restarting a container.
//
// Possible values are:
//
//   - always: the docker daemon will always restart the container
//   - on-failure: the docker daemon will restart the container on failures, at
//                 most MaximumRetryCount times
//   - no: the docker daemon will not restart the container automatically
type RestartPolicy struct {
	Name              string `json:"Name,omitempty" yaml:"Name,omitempty"`
	MaximumRetryCount int    `json:"MaximumRetryCount,omitempty" yaml:"MaximumRetryCount,omitempty"`
}

// HostConfig contains the container options related to starting a container on
// a given host
type HostConfig struct {
	Binds           []string               `json:"Binds,omitempty" yaml:"Binds,omitempty"`
	CapAdd          []string               `json:"CapAdd,omitempty" yaml:"CapAdd,omitempty"`
	CapDrop         []string               `json:"CapDrop,omitempty" yaml:"CapDrop,omitempty"`
	ContainerIDFile string                 `json:"ContainerIDFile,omitempty" yaml:"ContainerIDFile,omitempty"`
	LxcConf         []KeyValuePair         `json:"LxcConf,omitempty" yaml:"LxcConf,omitempty"`
	Privileged      bool                   `json:"Privileged,omitempty" yaml:"Privileged,omitempty"`
	PortBindings    map[Port][]PortBinding `json:"PortBindings,omitempty" yaml:"PortBindings,omitempty"`
	Links           []string               `json:"Links,omitempty" yaml:"Links,omitempty"`
	PublishAllPorts bool                   `json:"PublishAllPorts,omitempty" yaml:"PublishAllPorts,omitempty"`
	DNS             []string               `json:"Dns,omitempty" yaml:"Dns,omitempty"` // For Docker API v1.10 and above only
	DNSSearch       []string               `json:"DnsSearch,omitempty" yaml:"DnsSearch,omitempty"`
	ExtraHosts      []string               `json:"ExtraHosts,omitempty" yaml:"ExtraHosts,omitempty"`
	VolumesFrom     []string               `json:"VolumesFrom,omitempty" yaml:"VolumesFrom,omitempty"`
	NetworkMode     string                 `json:"NetworkMode,omitempty" yaml:"NetworkMode,omitempty"`
	RestartPolicy   RestartPolicy          `json:"RestartPolicy,omitempty" yaml:"RestartPolicy,omitempty"`
}

// Container represents a Docker container, constructed from the output of
// GET /containers/:id:/json.
type Container struct {
	client    *Client
	inspected bool

	ID              string            `json:"Id" yaml:"Id"`
	Created         time.Time         `json:"Created,omitempty" yaml:"Created,omitempty"`
	Path            string            `json:"Path,omitempty" yaml:"Path,omitempty"`
	Args            []string          `json:"Args,omitempty" yaml:"Args,omitempty"`
	Config          *Config           `json:"Config,omitempty" yaml:"Config,omitempty"`
	State           State             `json:"State,omitempty" yaml:"State,omitempty"`
	Image           string            `json:"Image,omitempty" yaml:"Image,omitempty"`
	NetworkSettings *NetworkSettings  `json:"NetworkSettings,omitempty" yaml:"NetworkSettings,omitempty"`
	SysInitPath     string            `json:"SysInitPath,omitempty" yaml:"SysInitPath,omitempty"`
	ResolvConfPath  string            `json:"ResolvConfPath,omitempty" yaml:"ResolvConfPath,omitempty"`
	HostnamePath    string            `json:"HostnamePath,omitempty" yaml:"HostnamePath,omitempty"`
	HostsPath       string            `json:"HostsPath,omitempty" yaml:"HostsPath,omitempty"`
	Name            string            `json:"Name,omitempty" yaml:"Name,omitempty"`
	Driver          string            `json:"Driver,omitempty" yaml:"Driver,omitempty"`
	Volumes         map[string]string `json:"Volumes,omitempty" yaml:"Volumes,omitempty"`
	VolumesRW       map[string]bool   `json:"VolumesRW,omitempty" yaml:"VolumesRW,omitempty"`
	HostConfig      *HostConfig       `json:"HostConfig,omitempty" yaml:"HostConfig,omitempty"`
}

// NewContainerFromId returns a container by given ID.
func NewContainerFromId(client *Client, id string) (*Container, error) {
	c, err := client.InspectContainer(id)
	if err != nil {
		return nil, fmt.Errorf("fail to inspect container(%s): %v", id, err)
	}
	c.client = client
	c.inspected = true
	return c, nil
}

//NewContainerFromPs returns a container object from the output of GET /containers/json.
func NewContainerFromPs(client *Client, apiContainer *APIContainers) *Container {
	return &Container{
		client:    client,
		inspected: false,
		ID:        apiContainer.ID,
		Image:     apiContainer.Image,
		Name:      GetApiContainerName(apiContainer),
	}
}

// CreateContainerOptions specify parameters to the CreateContainer function.
//
// See http://goo.gl/2xxQQK for more details.
type CreateContainerOptions struct {
	Name       string
	Config     *Config `qs:"-"`
	HostConfig *HostConfig
}

func valOrNil(val interface{}) string {
	if val == nil {
		return ""
	}
	return val.(string)
}

func parseBool(str string) bool {
	val, _ := strconv.ParseBool(str)
	return val
}

// CreateContainer creates new container by given options.
func CreateContainer(client *Client, options map[string]interface{}) (*Container, error) {
	// FIXME: many things need to be done.
	// https://docs.docker.com/reference/commandline/cli/#run
	createOptions := CreateContainerOptions{
		Name: options["name"].(string),
		Config: &Config{
			Hostname:     valOrNil(options["hostname"]),
			Domainname:   valOrNil(options["domainname"]),
			User:         valOrNil(options["user"]),
			Memory:       StrTo(valOrNil(options["memory"])).MustInt64(), // FIXME: parse unit?
			CPUShares:    StrTo(valOrNil(options["cpu-shares"])).MustInt64(),
			CPUSet:       valOrNil(options["cpuset"]),
			AttachStdin:  strings.Contains(valOrNil(options["attach"]), "STDIN"),
			AttachStdout: strings.Contains(valOrNil(options["attach"]), "STDOUT"),
			AttachStderr: strings.Contains(valOrNil(options["attach"]), "STDERR"),
			Tty:          parseBool(valOrNil(options["tty"])),
			OpenStdin:    parseBool(valOrNil(options["interactive"])),
			// Env:             valOrNil(options["env"]),
			// Dns:             valOrNil(options["dns"]),
			VolumesFrom: valOrNil(options["volumes-from"]),
			WorkingDir:  valOrNil(options["workdir"]),
			// Entrypoint:      valOrNil(options["entrypoint"]),
		},
	}

	// TODO: PortSpecs, ExposedPorts, Volumes
	c, err := client.CreateContainer(createOptions)
	if err != nil {
		return nil, err
	}
	return NewContainerFromId(client, c.ID)
}

func (c *Container) Stop() error {
	return c.client.StopContainer(c.ID, 60)
}

func (c *Container) Start() error {
	return c.client.StartContainer(c.ID, &HostConfig{})
}

func (c *Container) Wait() (int, error) {
	return c.client.WaitContainer(c.ID)
}

// Inspect inspects container information.
func (c *Container) Inspect() (err error) {
	c, err = c.client.InspectContainer(c.ID)
	if err != nil {
		return err
	}
	c.inspected = true
	return nil
}

func (c *Container) InspectIfNotInspected() error {
	if !c.inspected {
		return c.Inspect()
	}
	return nil
}

// Return a value from the container or None if the value is not set.
//:param key: a string using dotted notation for nested dictionary lookups
func (c *Container) Get(key string) interface{} {
	if err := c.InspectIfNotInspected(); err != nil {
		log.Printf("Fail to inspect container(%s): %v", c.Name, err)
		return ""
	}
	switch key {
	case "State.Running":
		return c.State.Running
	case "NetworkSettings.Ports":
		return c.NetworkSettings.Ports
	}
	return nil
}

// IsRunning returns true if container is running.
func (c *Container) IsRunning() bool {
	running, ok := c.Get("State.Running").(bool)
	return ok && running
}
