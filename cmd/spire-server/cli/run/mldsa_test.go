package run

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/stretchr/testify/require"
)

// These tests pin the fail-closed strict-profile configuration boundary. They
// are configuration tests, not deployment or security-review evidence.
func TestStrictPQServerConfiguration(t *testing.T) {
	logOptions := []log.Option{log.WithLevel("INFO")}

	writeConfig := func(t *testing.T, disableJWTSVIDs bool, caKeyType, jwtKeyType string, strict bool) string {
		t.Helper()
		dir := t.TempDir()
		config := fmt.Sprintf(`
server {
    bind_address = "127.0.0.1"
    bind_port = "8081"
    socket_path = "unix:///tmp/qspiffe-test-server.sock"
    log_level = "INFO"
    trust_domain = "pq.example"
    data_dir = %q
    ca_key_type = %q
    jwt_key_type = %q
    disable_jwt_svids = %t
    strict_pq = %t
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = %q
        }
    }
    KeyManager "disk" {
        plugin_data { keys_path = %q }
    }
}
`, dir, caKeyType, jwtKeyType, disableJWTSVIDs, strict, filepath.Join(dir, "datastore.sqlite3"), filepath.Join(dir, "keys.json"))
		path := filepath.Join(dir, "server.conf")
		require.NoError(t, os.WriteFile(path, []byte(config), 0600))
		return path
	}

	//nolint:unparam // the helper keeps an error return for call-site symmetry
	parse := func(t *testing.T, path string) (*Config, error) {
		t.Helper()
		c, err := ParseFile(path, false)
		require.NoError(t, err)
		return c, nil
	}

	t.Run("strict PQ accepted", func(t *testing.T) {
		path := writeConfig(t, true, "ml-dsa-65", "", true)
		c, err := parse(t, path)
		require.NoError(t, err)
		sc, err := NewServerConfig(c, logOptions, true)
		require.NoError(t, err)
		require.Equal(t, keymanager.MLDSA65, sc.CAKeyType)
		require.True(t, sc.StrictPQ)
		require.True(t, sc.TLSPolicy.RequirePQKEM, "strict_pq must require TLS 1.3 + PQ KEMs")
	})

	t.Run("strict PQ accepts the ML-DSA JWT profile", func(t *testing.T) {
		path := writeConfig(t, false, "ml-dsa-65", "", true)
		c, err := parse(t, path)
		require.NoError(t, err)
		sc, err := NewServerConfig(c, logOptions, true)
		require.NoError(t, err)
		require.Equal(t, keymanager.MLDSA65, sc.JWTKeyType)
		require.False(t, sc.DisableJWTSVIDs)
	})

	t.Run("strict PQ rejects a classical JWT key", func(t *testing.T) {
		path := writeConfig(t, false, "ml-dsa-65", "ec-p256", true)
		c, err := parse(t, path)
		require.NoError(t, err)
		_, err = NewServerConfig(c, logOptions, true)
		require.ErrorContains(t, err, "strict PQ requires jwt_key_type")
	})

	t.Run("classical CA with strict PQ rejected", func(t *testing.T) {
		path := writeConfig(t, true, "ec-p256", "", true)
		c, err := parse(t, path)
		require.NoError(t, err)
		_, err = NewServerConfig(c, logOptions, true)
		require.ErrorContains(t, err, "strict")
	})
}
