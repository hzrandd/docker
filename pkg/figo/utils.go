package figo

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// DockerUrl returns Docker API URL from environment variable.
func DockerUrl() string {
	url := os.Getenv("DOCKER_HOST")
	if len(url) > 0 {
		return url
	}
	return "unix:///var/run/docker.sock"
}

// IsFile returns true if given path is a file,
// or returns false when it's a directory or does not exist.
func IsFile(filePath string) bool {
	f, e := os.Stat(filePath)
	if e != nil {
		return false
	}
	return !f.IsDir()
}

// IsExist checks whether a file or directory exists.
// It returns false when the file or directory does not exist.
func IsExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

var UserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1541.0 Safari/537.36"

// HttpGet gets the specified resource. ErrNotFound is returned if the
// server responds with status 404.
func HttpGet(client *http.Client, url string, header http.Header) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 200 {
		return resp.Body, nil
	}
	resp.Body.Close()
	if resp.StatusCode == 404 { // 403 can be rate limit error.  || resp.StatusCode == 403 {
		err = fmt.Errorf("resource not found: %s", url)
	} else {
		err = fmt.Errorf("get %s -> %d", url, resp.StatusCode)
	}
	return nil, err
}

// HttpGetBytes gets the specified resource. ErrNotFound is returned if the server
// responds with status 404.
func HttpGetBytes(client *http.Client, url string, header http.Header) ([]byte, error) {
	rc, err := HttpGet(client, url, header)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return ioutil.ReadAll(rc)
}

type StreamOutput struct {
	Events []map[string]string
}

func NewStreamOutput() *StreamOutput {
	return &StreamOutput{
		Events: make([]map[string]string, 0),
	}
}

func (so *StreamOutput) Write(p []byte) (int, error) {
	e := make(map[string]string)
	for _, line := range bytes.Split(p, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal(line, &e); err != nil {
			return 0, err
		}
		fmt.Print(string(e["stream"]))
		so.Events = append(so.Events, e)
	}
	return len(p), nil
}

func parseEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, ErrInvalidEndpoint
	}
	if u.Scheme == "tcp" {
		_, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			if e, ok := err.(*net.AddrError); ok {
				if e.Err == "missing port in address" {
					return u, nil
				}
			}
			return nil, ErrInvalidEndpoint
		}
		number, err := strconv.ParseInt(port, 10, 64)
		if err == nil && number == 2376 {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "unix" {
		return nil, ErrInvalidEndpoint
	}
	if u.Scheme != "unix" {
		_, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			if e, ok := err.(*net.AddrError); ok {
				if e.Err == "missing port in address" {
					return u, nil
				}
			}
			return nil, ErrInvalidEndpoint
		}
		number, err := strconv.ParseInt(port, 10, 64)
		if err == nil && number > 0 && number < 65536 {
			return u, nil
		}
	} else {
		return u, nil // we don't need port when using a unix socket
	}
	return nil, ErrInvalidEndpoint
}

const (
	stdWriterPrefixLen = 8
	stdWriterFdIndex   = 0
	stdWriterSizeIndex = 4
)

var errInvalidStdHeader = errors.New("Unrecognized input header")

func stdCopy(dstout, dsterr io.Writer, src io.Reader) (written int64, err error) {
	var (
		buf       = make([]byte, 32*1024+stdWriterPrefixLen+1)
		bufLen    = len(buf)
		nr, nw    int
		er, ew    error
		out       io.Writer
		frameSize int
	)
	for {
		for nr < stdWriterPrefixLen {
			var nr2 int
			nr2, er = src.Read(buf[nr:])
			if er == io.EOF {
				if nr < stdWriterPrefixLen && nr2 < stdWriterPrefixLen {
					return written, nil
				}
				nr += nr2
				break
			} else if er != nil {
				return 0, er
			}
			nr += nr2
		}
		switch buf[stdWriterFdIndex] {
		case 0:
			fallthrough
		case 1:
			out = dstout
		case 2:
			out = dsterr
		default:
			return 0, errInvalidStdHeader
		}
		frameSize = int(binary.BigEndian.Uint32(buf[stdWriterSizeIndex : stdWriterSizeIndex+4]))
		if frameSize+stdWriterPrefixLen > bufLen {
			buf = append(buf, make([]byte, frameSize+stdWriterPrefixLen-len(buf)+1)...)
			bufLen = len(buf)
		}
		for nr < frameSize+stdWriterPrefixLen {
			var nr2 int
			nr2, er = src.Read(buf[nr:])
			if er == io.EOF {
				if nr == 0 {
					return written, nil
				}
				nr += nr2
				break
			} else if er != nil {
				return 0, er
			}
			nr += nr2
		}
		bound := frameSize + stdWriterPrefixLen
		if bound > nr {
			bound = nr
		}
		nw, ew = out.Write(buf[stdWriterPrefixLen:bound])
		if nw > 0 {
			written += int64(nw)
		}
		if ew != nil {
			return 0, ew
		}
		if nw != frameSize {
			return written, io.ErrShortWrite
		}
		copy(buf, buf[frameSize+stdWriterPrefixLen:])
		nr -= frameSize + stdWriterPrefixLen
	}
}

func queryString(opts interface{}) string {
	if opts == nil {
		return ""
	}
	value := reflect.ValueOf(opts)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return ""
	}
	items := url.Values(map[string][]string{})
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if field.PkgPath != "" {
			continue
		}
		key := field.Tag.Get("qs")
		if key == "" {
			key = strings.ToLower(field.Name)
		} else if key == "-" {
			continue
		}
		v := value.Field(i)
		switch v.Kind() {
		case reflect.Bool:
			if v.Bool() {
				items.Add(key, "1")
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if v.Int() > 0 {
				items.Add(key, strconv.FormatInt(v.Int(), 10))
			}
		case reflect.Float32, reflect.Float64:
			if v.Float() > 0 {
				items.Add(key, strconv.FormatFloat(v.Float(), 'f', -1, 64))
			}
		case reflect.String:
			if v.String() != "" {
				items.Add(key, v.String())
			}
		case reflect.Ptr:
			if !v.IsNil() {
				if b, err := json.Marshal(v.Interface()); err == nil {
					items.Add(key, string(b))
				}
			}
		}
	}
	return items.Encode()
}

// Convert string to specify type.
type StrTo string

func (f StrTo) Exist() bool {
	return string(f) != string(0x1E)
}

func (f StrTo) Uint8() (uint8, error) {
	v, err := strconv.ParseUint(f.String(), 10, 8)
	return uint8(v), err
}

func (f StrTo) Int() (int, error) {
	v, err := strconv.ParseInt(f.String(), 10, 32)
	return int(v), err
}

func (f StrTo) Int64() (int64, error) {
	v, err := strconv.ParseInt(f.String(), 10, 64)
	return int64(v), err
}

func (f StrTo) MustUint8() uint8 {
	v, _ := f.Uint8()
	return v
}

func (f StrTo) MustInt() int {
	v, _ := f.Int()
	return v
}

func (f StrTo) MustInt64() int64 {
	v, _ := f.Int64()
	return v
}

func (f StrTo) String() string {
	if f.Exist() {
		return string(f)
	}
	return ""
}

type argInt []int

func (a argInt) Get(i int, args ...int) (r int) {
	if i >= 0 && i < len(a) {
		r = a[i]
	} else if len(args) > 0 {
		r = args[0]
	}
	return
}

// Convert any type to string.
func ToStr(value interface{}, args ...int) (s string) {
	switch v := value.(type) {
	case bool:
		s = strconv.FormatBool(v)
	case float32:
		s = strconv.FormatFloat(float64(v), 'f', argInt(args).Get(0, -1), argInt(args).Get(1, 32))
	case float64:
		s = strconv.FormatFloat(v, 'f', argInt(args).Get(0, -1), argInt(args).Get(1, 64))
	case int:
		s = strconv.FormatInt(int64(v), argInt(args).Get(0, 10))
	case int8:
		s = strconv.FormatInt(int64(v), argInt(args).Get(0, 10))
	case int16:
		s = strconv.FormatInt(int64(v), argInt(args).Get(0, 10))
	case int32:
		s = strconv.FormatInt(int64(v), argInt(args).Get(0, 10))
	case int64:
		s = strconv.FormatInt(v, argInt(args).Get(0, 10))
	case uint:
		s = strconv.FormatUint(uint64(v), argInt(args).Get(0, 10))
	case uint8:
		s = strconv.FormatUint(uint64(v), argInt(args).Get(0, 10))
	case uint16:
		s = strconv.FormatUint(uint64(v), argInt(args).Get(0, 10))
	case uint32:
		s = strconv.FormatUint(uint64(v), argInt(args).Get(0, 10))
	case uint64:
		s = strconv.FormatUint(v, argInt(args).Get(0, 10))
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		s = fmt.Sprintf("%v", v)
	}
	return s
}

// GetApiContainerName returns name of API container.
func GetApiContainerName(apiContainer *APIContainers) string {
	for _, name := range apiContainer.Names {
		infos := strings.Split(name, "/")
		if len(infos) == 2 {
			return infos[1]
		}
	}
	return ""
}

var apiContainerNamePattern = regexp.MustCompile(`^([^_]+)_([^_]+)_(run_)?(\d+)$`)

// IsValidContainerName returns true if given name is a valid container name.
func IsValidContainerName(name string, oneOff bool) bool {
	m := apiContainerNamePattern.FindAllStringSubmatch(name, -1)
	if m == nil {
		return false
	}
	if oneOff {
		return m[0][2] == "run_"
	}
	return len(m[0][2]) == 0
}

// ParseContainerName parses and returns container name.
func ParseContainerName(name string) (string, string, int) {
	m := apiContainerNamePattern.FindAllStringSubmatch(name, -1)
	return m[0][0], m[0][1], StrTo(m[0][3]).MustInt()
}

// ParseArgs returns options and services' name from command line arguments.
// FIXME: parse slice values
func ParseArgs(args []string) (entries []string, _ map[string]string) {
	log.Println("ParseArgs has limitations and bugs! Cannot handle all the arguments.")
	options := map[string]string{}
	for _, arg := range args {
		if strings.Contains(arg, "=") {
			infos := strings.SplitN(arg, "=", 2)
			options[strings.TrimLeft(infos[0], "-")] = infos[1]
		} else {
			entries = append(entries, arg)
		}
	}
	return entries, options
}

type ConfigurationError struct {
	Msg string
}

func (e ConfigurationError) Error() string {
	return e.Msg
}

// ParseVolumeSpec parses and returns given volume configuration.
func ParseVolumeSpec(config string) ([]string, error) {
	infos := strings.Split(config, ":")
	if len(infos) > 3 {
		return nil, ConfigurationError{fmt.Sprintf("Volume %s has incorrect format, should be external:internal[:mode]", config)}
	} else if len(infos) == 1 {
		return []string{"", infos[0], "rw"}, nil
	}

	if len(infos) == 2 {
		infos = append(infos, "rw")
	}

	if infos[2] != "rw" && infos[2] != "ro" {
		return nil, ConfigurationError{fmt.Sprintf("Volume %s has invalid mode (%s), should be one of: rw, ro", config, infos[2])}
	}
	return infos, nil
}
