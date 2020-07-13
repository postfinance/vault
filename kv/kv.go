// Package kv provides version agnostic methods for read, write and list of secrets from @hashicorp Vault's KV secret engines
package kv

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Constants
const (
	ReadPrefix  = "data"
	WritePrefix = ReadPrefix
	ListPrefix  = "metadata"
)

// Client represents a KV client
type Client struct {
	client  *api.Client
	Version int
	Mount   string
}

// New creates a new kv.Client with the Vault client c and a path p long enough to determine the mount path of the engine
// p = secret/ -> K/V engine mount path secret/
// p = secret  -> error
// p = /secret -> error
func New(c *api.Client, p string) (*Client, error) {
	if strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("path %s must not start with '/'", p)
	}
	if !strings.ContainsRune(p, '/') {
		return nil, fmt.Errorf("path %s must contain at least one '/'", p)
	}
	version, mount, err := getVersionAndMount(c, p)
	if err != nil {
		return nil, err
	}
	return &Client{client: c, Version: version, Mount: mount}, nil
}

// Client returns a Vault *api.Client
func (c *Client) Client() *api.Client {
	return c.client
}

// Read a secret from a K/V version 1 or 2
func (c *Client) Read(p string) (map[string]interface{}, error) {
	if c.Version == 2 {
		p = FixPath(p, c.Mount, ReadPrefix)
	}
	s, err := c.client.Logical().Read(p)
	if err != nil {
		return nil, err
	}
	if s == nil || s.Data == nil {
		return nil, nil
	}
	if c.Version == 2 {
		return s.Data["data"].(map[string]interface{}), nil
	}
	return s.Data, nil
}

// Write a secret to a K/V version 1 or 2
func (c *Client) Write(p string, data map[string]interface{}) error {
	if c.Version == 2 {
		p = FixPath(p, c.Mount, WritePrefix)
		data = map[string]interface{}{
			"data": data,
		}
	}
	_, err := c.client.Logical().Write(p, data)
	return err
}

// List secrets from a K/V version 1 or 2
func (c *Client) List(p string) ([]string, error) {
	if c.Version == 2 {
		p = FixPath(p, c.Mount, ListPrefix)
	}
	s, err := c.client.Logical().List(p)
	if err != nil {
		return nil, err
	}
	if s == nil || s.Data == nil {
		return nil, nil
	}
	keys := []string{}
	for _, v := range s.Data["keys"].([]interface{}) {
		keys = append(keys, v.(string))
	}
	return keys, nil
}

// SetToken sets the token directly. This won't perform any auth
// verification, it simply sets the token properly for future requests.
func (c *Client) SetToken(v string) {
	c.client.SetToken(v)
}

// FixPath inserts the API prefix for v1 style path
// secret/foo      -> secret/data/foo
// secret/data/foo -> secret/data/foo
// presumes a valid path
func FixPath(path, mount, prefix string) string {
	if !strings.HasSuffix(mount, "/") {
		mount = mount + "/"
	}
	secretPath := strings.TrimPrefix(path, mount)
	pp := strings.Split(secretPath, "/")
	if pp[0] == prefix {
		return path // already v2 style path
	}
	return fmt.Sprintf("%s%s/%s", mount, prefix, secretPath)
}

// getVersionAndMount of the KV engine
func getVersionAndMount(c *api.Client, p string) (int, string, error) {
	mounts, err := c.Sys().ListMounts()
	if err != nil {
		return 0, "", err
	}
	for k, m := range mounts {
		if !strings.HasPrefix(p, k) {
			continue
		}
		switch m.Type {
		case "kv":
			version, err := strconv.Atoi(m.Options["version"])
			if err != nil {
				return 0, "", err
			}
			return version, k, nil
		case "generic":
			return 1, k, nil
		default:
			return 0, "", fmt.Errorf("matching mount %s for path %s is not of type kv", k, p)
		}
	}
	return 0, "", fmt.Errorf("failed to get mount for path: %s", p)
}
