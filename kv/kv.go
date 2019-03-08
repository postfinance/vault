package kv

import (
	"fmt"
	"path"
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
}

// New returns a new Client
func New(c *api.Client, p string) (*Client, error) {
	version, err := getVersion(c, p)
	if err != nil {
		return nil, err
	}
	return &Client{client: c, Version: version}, nil
}

// Read a secret from a K/V version 1/2
func (c *Client) Read(p string) (map[string]interface{}, error) {
	origPath := p
	if c.Version == 2 {
		p = fixPath(p, ReadPrefix)
	}
	s, err := c.client.Logical().Read(p)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("failed to read path %s", origPath)
	}
	if c.Version == 2 {
		return s.Data["data"].(map[string]interface{}), nil
	}
	return s.Data, nil
}

// Write a secret to a K/V version 1/2
func (c *Client) Write(p string, data map[string]interface{}) error {
	if c.Version == 2 {
		p = fixPath(p, WritePrefix)
		data = map[string]interface{}{
			"data": data,
		}
	}
	_, err := c.client.Logical().Write(p, data)
	return err
}

// List secrets from a K/V version 1/2
func (c *Client) List(p string) ([]string, error) {
	origPath := p
	if c.Version == 2 {
		p = fixPath(p, ListPrefix)
	}
	s, err := c.client.Logical().List(p)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("failed to list path %s", origPath)
	}
	keys := []string{}
	for _, v := range s.Data["keys"].([]interface{}) {
		keys = append(keys, v.(string))
	}
	return keys, nil
}

// fixPath inserts the API prefix if necessary
func fixPath(p, prefix string) string {
	pp := strings.Split(p, "/")
	return path.Join(append(pp[:1], append([]string{prefix}, pp[1:]...)...)...)
}

// getVersion of the KV engine
func getVersion(c *api.Client, p string) (int, error) {
	var version int
	mounts, err := c.Sys().ListMounts()
	if err != nil {
		return version, err
	}
	for k, m := range mounts {
		if !strings.HasPrefix(p, k) {
			continue
		}
		if m.Type != "kv" {
			return version, fmt.Errorf("matching mount %s for path %s is not of type kv", k, p)
		}
		version, err := strconv.Atoi(m.Options["version"])
		if err != nil {
			return version, err
		}
		switch version {
		case 1, 2:
			return version, nil
		default:
			return version, fmt.Errorf("unknown version: %d", version)
		}
	}
	return version, fmt.Errorf("failed to get mount for path: %s", p)
}
