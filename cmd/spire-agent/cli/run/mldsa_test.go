package run

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/stretchr/testify/require"
)

func TestStrictPQAgentConfiguration(t *testing.T) {
	logOptions := []log.Option{log.WithLevel("INFO")}
	dir := t.TempDir()

	writeConfig := func(t *testing.T, body string) string {
		t.Helper()
		config := fmt.Sprintf(`
agent {
    data_dir = %q
    server_address = "127.0.0.1"
    server_port = 8081
    socket_path = %q
    trust_bundle_path = %q
    trust_bundle_format = "pem"
    trust_domain = "pq.example"
    log_level = "INFO"
%s
}
plugins {
    KeyManager "disk" {
        plugin_data { directory = %q }
    }
}
`, filepath.Join(dir, "data"), filepath.Join(dir, "api.sock"), filepath.Join(dir, "bundle.pem"), body, filepath.Join(dir, "keys"))
		path := filepath.Join(dir, "agent.conf")
		require.NoError(t, os.WriteFile(path, []byte(config), 0600))
		return path
	}

	parse := func(t *testing.T, path string) *Config {
		t.Helper()
		c, err := ParseFile(path, false)
		require.NoError(t, err)
		return c
	}

	strict := `    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"`

	t.Run("strict PQ accepted", func(t *testing.T) {
		c := parse(t, writeConfig(t, strict))
		ac, err := NewAgentConfig(c, logOptions, true)
		require.NoError(t, err)
		require.True(t, ac.TLSPolicy.RequirePQKEM)
		require.Equal(t, keymanager.MLDSA65, ac.AgentSVIDKeyType)
		require.Equal(t, workloadkey.MLDSA65, ac.WorkloadKeyType)
	})

	t.Run("insecure bootstrap rejected", func(t *testing.T) {
		c := parse(t, writeConfig(t, strict+"\n    insecure_bootstrap = true"))
		_, err := NewAgentConfig(c, logOptions, true)
		require.ErrorContains(t, err, "insecure_bootstrap")
	})

	t.Run("classical agent SVID key rejected", func(t *testing.T) {
		c := parse(t, writeConfig(t, `    strict_pq = true
    agent_svid_key_type = "ec-p256"
    workload_x509_svid_key_type = "ml-dsa-65"`))
		_, err := NewAgentConfig(c, logOptions, true)
		require.ErrorContains(t, err, "agent_svid_key_type")
	})

	t.Run("classical workload key rejected", func(t *testing.T) {
		c := parse(t, writeConfig(t, `    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ec-p256"`))
		_, err := NewAgentConfig(c, logOptions, true)
		require.ErrorContains(t, err, "workload_x509_svid_key_type")
	})
}
