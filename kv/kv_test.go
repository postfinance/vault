package kv_test

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
	"github.com/pkg/errors"
	"github.com/postfinance/vault/kv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rootToken  = "90b03685-e17b-7e5e-13a0-e14e45baeb2f"
	secretpath = "secret/test"
)

var (
	host        string
	vaultClient *api.Client
	secrets     = map[string]map[string]interface{}{
		path.Join(secretpath, "first"): {
			"Penguin": "Oswald Chesterfield Cobblepot",
		},
		path.Join(secretpath, "second"): {
			"Two-Face":   "Harvey Dent",
			"Poison Ivy": "Pamela Lillian Isley",
		},
	}
)

func TestMain(m *testing.M) {
	flag.Parse()
	//os.Unsetenv("http_proxy")
	//os.Unsetenv("https_proxy")

	pool, err := dockertest.NewPool("unix:///var/run/docker.sock")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.Run("vault", "latest", []string{
		"VAULT_DEV_ROOT_TOKEN_ID=" + rootToken,
		"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
	})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	host = os.Getenv("DOCKER_HOST")
	if host == "" {
		host = "localhost"
	}
	if host != "localhost" && !strings.Contains(host, ".") {
		host = host + ".pnet.ch"
	}
	vaultAddr := fmt.Sprintf("http://%s:%s", host, resource.GetPort("8200/tcp"))

	os.Setenv("VAULT_ADDR", vaultAddr)
	os.Setenv("VAULT_TOKEN", rootToken)

	fmt.Println("VAULT_ADDR:", vaultAddr)

	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		log.Fatal(err)
	}
	vaultClient, err = api.NewClient(vaultConfig)
	if err != nil {
		log.Fatal(err)
	}

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		_, err = vaultClient.Sys().ListMounts()
		return err
	}); err != nil {
		log.Fatal(errors.Wrap(err, "could not connect to vault in docker"))
	}

	code := m.Run()

	// You can't defer this because os.Exit doesn't care for defer
	if err := pool.Purge(resource); err != nil {
		log.Fatalf("could not purge resource: %s", err)
	}
	os.Exit(code)
}

func TestVaultKV(t *testing.T) {
	var clnt *kv.Client

	t.Run("test FixPath with v1 style path", func(t *testing.T) {
		p := "secret/foo"
		assert.Equal(t, "secret/data/foo", kv.FixPath(p, "secret/", kv.ReadPrefix))
	})

	t.Run("test FixPath with v2 style path", func(t *testing.T) {
		p := "secret/data/foo"
		assert.Equal(t, p, kv.FixPath(p, "secret", kv.ReadPrefix))
	})

	t.Run("test FixPath with nested secret engine", func(t *testing.T) {
		p := "secret/foo/kv/bar"
		mount := "secret/foo/kv/"
		expected := "secret/foo/kv/data/bar"
		assert.Equal(t, expected, kv.FixPath(p, mount, kv.ReadPrefix))
	})

	t.Run("new client with false path", func(t *testing.T) {
		c, err := kv.New(vaultClient, "secret")
		assert.Nil(t, c)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "path secret must contain at least one '/'")
	})

	t.Run("new client with false path", func(t *testing.T) {
		c, err := kv.New(vaultClient, "cubbyhole/")
		assert.Nil(t, c)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "matching mount cubbyhole/ for path cubbyhole/ is not of type kv")
	})

	t.Run("new client with false path", func(t *testing.T) {
		c, err := kv.New(vaultClient, "notexist/")
		assert.Nil(t, c)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "failed to get mount for path: notexist/")
	})

	t.Run("new client with path that starts with '/'", func(t *testing.T) {
		c, err := kv.New(vaultClient, "/secret")
		assert.Nil(t, c)
		assert.Error(t, err)
	})

	t.Run("new client", func(t *testing.T) {
		c, err := kv.New(vaultClient, "secret/")
		require.NotNil(t, c)
		require.NoError(t, err)
		clnt = c
	})

	t.Run("write secrets", func(t *testing.T) {
		for name, data := range secrets {
			assert.NoError(t, clnt.Write(name, data))
		}
	})

	t.Run("read secrets", func(t *testing.T) {
		for name, data := range secrets {
			s, err := clnt.Read(name)
			assert.NoError(t, err)
			assert.Equal(t, data, s)
		}
	})

	t.Run("read path not found", func(t *testing.T) {
		s, err := clnt.Read(secretpath)
		assert.Nil(t, s)
		assert.Nil(t, err)
	})

	t.Run("list path", func(t *testing.T) {
		keys, err := clnt.List(secretpath)
		assert.NoError(t, err)
		assert.Len(t, keys, len(secrets))
		for name := range secrets {
			assert.Contains(t, keys, path.Base(name))
		}
	})

	t.Run("list secret not found", func(t *testing.T) {
		for name := range secrets {
			keys, err := clnt.List(name)
			assert.Nil(t, keys)
			assert.Nil(t, err)
			break
		}
	})

	data := map[string]interface{}{
		"Harley Quinn": "Dr. Harleen Frances Quinzel",
	}
	t.Run("write secret to path entry", func(t *testing.T) {
		err := clnt.Write(secretpath, data)
		assert.NoError(t, err)
	})

	t.Run("write secret to path entry", func(t *testing.T) {
		s, err := clnt.Read(secretpath)
		assert.NoError(t, err)
		assert.Equal(t, data, s)
	})
}
