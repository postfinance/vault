package k8s

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rootToken = "90b03685-e17b-7e5e-13a0-e14e45baeb2f"
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

	host := os.Getenv("DOCKER_HOST")
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
	vaultClient, err := api.NewClient(vaultConfig)
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

func TestFixAuthMountPath(t *testing.T) {
	testData := [][2]string{
		[2]string{"kubernetes", "auth/kubernetes"},
		[2]string{"/kubernetes", "auth/kubernetes"},
		[2]string{"/kubernetes/", "auth/kubernetes"},
		[2]string{"kubernetes/", "auth/kubernetes"},
		[2]string{"kubernetes/something", "auth/kubernetes/something"},
		[2]string{"auth/kubernetes", "auth/kubernetes"},
		[2]string{"/auth/kubernetes", "auth/kubernetes"},
	}

	for _, td := range testData {
		t.Log(td[0])
		assert.Equal(t, td[1], FixAuthMountPath(td[0]))
	}
}

func TestNewVaultFromEnvironment(t *testing.T) {
	vaultTokenPath, err := ioutil.TempFile("", "vault-token")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(vaultTokenPath.Name())

	t.Run("without minimal attributes", func(t *testing.T) {
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("with minimal attributes", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, "", v.Role)
		assert.Equal(t, vaultTokenPath.Name(), v.TokenPath)
		assert.Equal(t, false, v.ReAuth)
		assert.Equal(t, 0, v.TTL)
		assert.Equal(t, AuthMountPath, v.AuthMountPath)
		assert.Equal(t, ServiceAccountTokenPath, v.ServiceAccountTokenPath)
		assert.Equal(t, false, v.AllowFail)
	})

	t.Run("invalid VAULT_TTL", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_TTL", "1std")
		defer os.Setenv("VAULT_TTL", "")
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid VAULT_TTL", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_TTL", "1h")
		defer os.Setenv("VAULT_TTL", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, 3600, v.TTL)
	})

	t.Run("invalid VAULT_REAUTH", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_REAUTH", "no")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid VAULT_REAUTH", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_REAUTH", "true")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, true, v.ReAuth)
	})

	t.Run("invalid ALLOW_FAIL", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("ALLOW_FAIL", "no")
		defer os.Setenv("ALLOW_FAIL", "")
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid ALLOW_FAIL", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("ALLOW_FAIL", "true")
		defer os.Setenv("ALLOW_FAIL", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, true, v.AllowFail)
	})
}

func TestToken(t *testing.T) {

	t.Run("failed to store token", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", "/not/existing/path")
		v, err := NewFromEnvironment()
		assert.NoError(t, err)
		assert.NotNil(t, v)
		assert.Error(t, v.StoreToken(rootToken))
	})

	t.Run("failed to load token", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", "/not/existing/path")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.LoadToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("load empty token", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(""))
		token, err := v.LoadToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("store and load token", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(rootToken))
		token, err := v.LoadToken()
		assert.NoError(t, err)
		assert.Equal(t, rootToken, token)
	})

	t.Run("failed to get token without ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_REAUTH", "false")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed to renew token without ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_REAUTH", "false")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(rootToken))
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("successful renew token without ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_REAUTH", "false")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		// create a new token
		v.UseToken(rootToken)
		secret, err := v.Client().Auth().Token().CreateOrphan(&api.TokenCreateRequest{
			TTL: "3600s",
		})
		assert.NoError(t, err)
		// store the new token
		require.NoError(t, v.StoreToken(secret.Auth.ClientToken))
		// the actual test
		token, err := v.GetToken()
		assert.NoError(t, err)
		assert.Equal(t, secret.Auth.ClientToken, token)
	})
}

func TestAuthenticate(t *testing.T) {
	vaultTokenPath, err := ioutil.TempFile("", "vault-token")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(vaultTokenPath.Name())
	serviceAccountTokenPath, err := ioutil.TempFile("", "sa-token")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(serviceAccountTokenPath.Name())

	t.Run("failed to load service account token", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "/not/existing/path")
		defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.Authenticate()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed authentication", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", serviceAccountTokenPath.Name())
		defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.Authenticate()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("successful authentication", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", serviceAccountTokenPath.Name())
		defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		vaultLogicalBackup := vaultLogical
		vaultLogical = func(c *api.Client) vaultLogicalWriter {
			return &fakeWriter{}
		}
		defer func() { vaultLogical = vaultLogicalBackup }()
		token, err := v.Authenticate()
		assert.NoError(t, err)
		assert.Equal(t, rootToken, token)
	})

	t.Run("failed authentication with warnings", func(t *testing.T) {
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", serviceAccountTokenPath.Name())
		defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		vaultLogicalBackup := vaultLogical
		vaultLogical = func(c *api.Client) vaultLogicalWriter {
			return &fakeWriterWithWarnings{}
		}
		defer func() { vaultLogical = vaultLogicalBackup }()
		token, err := v.Authenticate()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed to get token with ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_REAUTH", "true")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed to renew token with ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_REAUTH", "true")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(rootToken))
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})
}

func TestRenew(t *testing.T) {

	t.Run("failed to get renewer", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		// the actual test
		r, err := v.NewRenewer(rootToken)
		assert.Error(t, err)
		assert.Nil(t, r)
	})

	t.Run("failed to get renewer", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		os.Setenv("VAULT_REAUTH", "false")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		// create a new token
		v.UseToken(rootToken)
		secret, err := v.Client().Auth().Token().CreateOrphan(&api.TokenCreateRequest{
			TTL: "3600s",
		})
		assert.NoError(t, err)
		r, err := v.NewRenewer(secret.Auth.ClientToken)
		assert.NoError(t, err)
		assert.NotNil(t, r)
	})
}

type fakeWriter struct{}

func (f *fakeWriter) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	return &api.Secret{
		Auth: &api.SecretAuth{
			ClientToken: rootToken,
		},
	}, nil
}

type fakeWriterWithWarnings struct{}

func (f *fakeWriterWithWarnings) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	return &api.Secret{
		Warnings: []string{"warning"},
	}, nil
}
