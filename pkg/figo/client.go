package figo

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/fileutils"
)

const userAgent = "go-dockerclient"

var (
	// ErrInvalidEndpoint is returned when the endpoint is not a valid HTTP URL.
	ErrInvalidEndpoint = errors.New("invalid endpoint")
	// ErrConnectionRefused is returned when the client cannot connect to the given endpoint.
	ErrConnectionRefused = errors.New("cannot connect to Docker endpoint")
	// ErrNoSuchImage is the error returned when the image does not exist.
	ErrNoSuchImage = errors.New("no such image")
	// ErrMissingRepo is the error returned when the remote repository is
	// missing.
	ErrMissingRepo = errors.New("missing remote repository e.g. 'github.com/user/repo'")
	// ErrMissingOutputStream is the error returned when no output stream
	// is provided to some calls, like BuildImage.
	ErrMissingOutputStream = errors.New("missing output stream")
	// ErrMultipleContexts is the error returned when both a ContextDir and
	// InputStream are provided in BuildImageOptions
	ErrMultipleContexts = errors.New("image build may not be provided BOTH context dir and input stream")
)

// Error represents failures in the API. It represents a failure from the API.
type Error struct {
	Status  int
	Message string
}

func newError(status int, body []byte) *Error {
	return &Error{Status: status, Message: string(body)}
}

func (e *Error) Error() string {
	return fmt.Sprintf("API error (%d): %s", e.Status, e.Message)
}

type Client struct {
	HTTPClient  *http.Client
	TLSConfig   *tls.Config
	endpoint    string
	endpointURL *url.URL
}

// NewClient returns a Client instance ready for communication with the given
// server endpoint. It will use the latest remote API version available in the
// server.
func NewClient(endpoint string) (*Client, error) {
	u, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return &Client{
		HTTPClient:  http.DefaultClient,
		endpoint:    endpoint,
		endpointURL: u,
	}, nil
}

func (c *Client) getURL(path string) string {
	urlStr := strings.TrimRight(c.endpointURL.String(), "/")
	if c.endpointURL.Scheme == "unix" {
		urlStr = ""
	}
	return fmt.Sprintf("%s%s", urlStr, path)
}

func (c *Client) do(method, path string, data interface{}) ([]byte, int, error) {
	var params io.Reader
	if data != nil {
		buf, err := json.Marshal(data)
		if err != nil {
			return nil, -1, err
		}
		params = bytes.NewBuffer(buf)
	}
	req, err := http.NewRequest(method, c.getURL(path), params)
	if err != nil {
		return nil, -1, err
	}
	req.Header.Set("User-Agent", userAgent)
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	} else if method == "POST" {
		req.Header.Set("Content-Type", "plain/text")
	}
	var resp *http.Response
	protocol := c.endpointURL.Scheme
	address := c.endpointURL.Path
	if protocol == "unix" {
		dial, err := net.Dial(protocol, address)
		if err != nil {
			return nil, -1, err
		}
		defer dial.Close()
		clientconn := httputil.NewClientConn(dial, nil)
		resp, err = clientconn.Do(req)
		if err != nil {
			return nil, -1, err
		}
		defer clientconn.Close()
	} else {
		resp, err = c.HTTPClient.Do(req)
	}
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return nil, -1, ErrConnectionRefused
		}
		return nil, -1, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, -1, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, resp.StatusCode, newError(resp.StatusCode, body)
	}
	return body, resp.StatusCode, nil
}

// NoSuchContainer is the error returned when a given container does not exist.
type NoSuchContainer struct {
	ID string
}

func (err *NoSuchContainer) Error() string {
	return "No such container: " + err.ID
}

// InspectContainer returns information about a container by its ID.
//
// https://docs.docker.com/reference/api/docker_remote_api_v1.15/#inspect-a-container
func (c *Client) InspectContainer(id string) (*Container, error) {
	path := "/containers/" + id + "/json"
	body, status, err := c.do("GET", path, nil)
	if status == http.StatusNotFound {
		return nil, &NoSuchContainer{ID: id}
	}
	if err != nil {
		return nil, err
	}
	var container Container
	err = json.Unmarshal(body, &container)
	if err != nil {
		return nil, err
	}
	return &container, nil
}

// AuthConfiguration represents authentication options to use in the PushImage
// method. It represents the authentication in the Docker index server.
type AuthConfiguration struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Email         string `json:"email,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"`
}

// AuthConfigurations represents authentication options to use for the
// PushImage method accommodating the new X-Registry-Config header
type AuthConfigurations struct {
	Configs map[string]AuthConfiguration `json:"configs"`
}

// BuildImageOptions present the set of informations available for building an
// image from a tarfile with a Dockerfile in it.
//
// For more details about the Docker building process, see
// http://goo.gl/tlPXPu.
type BuildImageOptions struct {
	Name                string             `qs:"t"`
	NoCache             bool               `qs:"nocache"`
	SuppressOutput      bool               `qs:"q"`
	RmTmpContainer      bool               `qs:"rm"`
	ForceRmTmpContainer bool               `qs:"forcerm"`
	InputStream         io.Reader          `qs:"-"`
	OutputStream        io.Writer          `qs:"-"`
	RawJSONStream       bool               `qs:"-"`
	Remote              string             `qs:"remote"`
	Auth                AuthConfiguration  `qs:"-"` // for older docker X-Registry-Auth header
	AuthConfigs         AuthConfigurations `qs:"-"` // for newer docker X-Registry-Config header
	ContextDir          string             `qs:"-"`
}

func headersWithAuth(auths ...interface{}) map[string]string {
	var headers = make(map[string]string)
	for _, auth := range auths {
		switch auth.(type) {
		case AuthConfiguration:
			var buf bytes.Buffer
			json.NewEncoder(&buf).Encode(auth)
			headers["X-Registry-Auth"] = base64.URLEncoding.EncodeToString(buf.Bytes())
		case AuthConfigurations:
			var buf bytes.Buffer
			json.NewEncoder(&buf).Encode(auth)
			headers["X-Registry-Config"] = base64.URLEncoding.EncodeToString(buf.Bytes())
		}
	}
	return headers
}

func parseDockerignore(root string) ([]string, error) {
	var excludes []string
	ignore, err := ioutil.ReadFile(path.Join(root, ".dockerignore"))
	if err != nil && !os.IsNotExist(err) {
		return excludes, fmt.Errorf("error reading .dockerignore: '%s'", err)
	}
	for _, pattern := range strings.Split(string(ignore), "\n") {
		matches, err := filepath.Match(pattern, "Dockerfile")
		if err != nil {
			return excludes, fmt.Errorf("bad .dockerignore pattern: '%s', error: %s", pattern, err)
		}
		if matches {
			return excludes, fmt.Errorf("dockerfile was excluded by .dockerignore pattern '%s'", pattern)
		}
		excludes = append(excludes, pattern)
	}
	return excludes, nil
}

// validateContextDirectory checks if all the contents of the directory
// can be read and returns an error if some files can't be read.
// Symlinks which point to non-existing files don't trigger an error
func validateContextDirectory(srcPath string, excludes []string) error {
	return filepath.Walk(filepath.Join(srcPath, "."), func(filePath string, f os.FileInfo, err error) error {
		// skip this directory/file if it's not in the path, it won't get added to the context
		if relFilePath, err := filepath.Rel(srcPath, filePath); err != nil {
			return err
		} else if skip, err := fileutils.Matches(relFilePath, excludes); err != nil {
			return err
		} else if skip {
			if f.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err != nil {
			if os.IsPermission(err) {
				return fmt.Errorf("can't stat '%s'", filePath)
			}
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		// skip checking if symlinks point to non-existing files, such symlinks can be useful
		// also skip named pipes, because they hanging on open
		if f.Mode()&(os.ModeSymlink|os.ModeNamedPipe) != 0 {
			return nil
		}
		if !f.IsDir() {
			currentFile, err := os.Open(filePath)
			if err != nil && os.IsPermission(err) {
				return fmt.Errorf("no permission to read from '%s'", filePath)
			}
			currentFile.Close()
		}
		return nil
	})
}

func createTarStream(srcPath string) (io.ReadCloser, error) {
	excludes, err := parseDockerignore(srcPath)
	if err != nil {
		return nil, err
	}
	if err := validateContextDirectory(srcPath, excludes); err != nil {
		return nil, err
	}
	tarOpts := &archive.TarOptions{
		Excludes:    excludes,
		Compression: archive.Uncompressed,
		NoLchown:    true,
	}
	return archive.TarWithOptions(srcPath, tarOpts)
}

type jsonMessage struct {
	Status   string `json:"status,omitempty"`
	Progress string `json:"progress,omitempty"`
	Error    string `json:"error,omitempty"`
	Stream   string `json:"stream,omitempty"`
}

func (c *Client) stream(method, path string, setRawTerminal, rawJSONStream bool, headers map[string]string, in io.Reader, stdout, stderr io.Writer) error {
	if (method == "POST" || method == "PUT") && in == nil {
		in = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.getURL(path), in)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	if method == "POST" {
		req.Header.Set("Content-Type", "plain/text")
	}
	for key, val := range headers {
		req.Header.Set(key, val)
	}
	var resp *http.Response
	protocol := c.endpointURL.Scheme
	address := c.endpointURL.Path
	if stdout == nil {
		stdout = ioutil.Discard
	}
	if stderr == nil {
		stderr = ioutil.Discard
	}
	if protocol == "unix" {
		dial, err := net.Dial(protocol, address)
		if err != nil {
			return err
		}
		clientconn := httputil.NewClientConn(dial, nil)
		resp, err = clientconn.Do(req)
		defer clientconn.Close()
	} else {
		resp, err = c.HTTPClient.Do(req)
	}
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return ErrConnectionRefused
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return newError(resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Type") == "application/json" {
		// if we want to get raw json stream, just copy it back to output
		// without decoding it
		if rawJSONStream {
			_, err = io.Copy(stdout, resp.Body)
			return err
		}
		dec := json.NewDecoder(resp.Body)
		for {
			var m jsonMessage
			if err := dec.Decode(&m); err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			if m.Stream != "" {
				fmt.Fprint(stdout, m.Stream)
			} else if m.Progress != "" {
				fmt.Fprintf(stdout, "%s %s\r", m.Status, m.Progress)
			} else if m.Error != "" {
				return errors.New(m.Error)
			}
			if m.Status != "" {
				fmt.Fprintln(stdout, m.Status)
			}
		}
	} else {
		if setRawTerminal {
			_, err = io.Copy(stdout, resp.Body)
		} else {
			_, err = stdCopy(stdout, stderr, resp.Body)
		}
		return err
	}
	return nil
}

// BuildImage builds an image from a tarball's url or a Dockerfile in the input
// stream.
//
// See http://goo.gl/wRsW76 for more details.
func (c *Client) BuildImage(opts BuildImageOptions) error {
	if opts.OutputStream == nil {
		return ErrMissingOutputStream
	}
	var headers = headersWithAuth(opts.Auth, opts.AuthConfigs)
	if opts.Remote != "" && opts.Name == "" {
		opts.Name = opts.Remote
	}
	if opts.InputStream != nil || opts.ContextDir != "" {
		headers["Content-Type"] = "application/tar"
	} else if opts.Remote == "" {
		return ErrMissingRepo
	}
	if opts.ContextDir != "" {
		if opts.InputStream != nil {
			return ErrMultipleContexts
		}
		var err error
		if opts.InputStream, err = createTarStream(opts.ContextDir); err != nil {
			return err
		}
	}
	return c.stream("POST", fmt.Sprintf("/build?%s",
		queryString(&opts)), true, opts.RawJSONStream, headers, opts.InputStream, opts.OutputStream, nil)
}
