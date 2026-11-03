package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	prommetrics "github.com/hashicorp/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/pkg/common/util"
)

type prometheusRunner struct {
	c                        *PrometheusConfig
	log                      logrus.FieldLogger
	server                   *http.Server
	ownedTLS                 *tlsconfig.Config
	sink                     Sink
	tlsPolicy                tlspolicy.Policy
	getX509SVID              func() (*x509svid.SVID, error)
	getX509BundleAuthorities func(spiffeid.TrustDomain) ([]*x509.Certificate, error)
}

func newPrometheusRunner(c *MetricsConfig) (sinkRunner, error) {
	runner := &prometheusRunner{
		c:                        c.FileConfig.Prometheus,
		log:                      c.Logger,
		tlsPolicy:                c.TLSPolicy,
		getX509SVID:              c.GetX509SVID,
		getX509BundleAuthorities: c.GetX509BundleAuthorities,
	}

	if runner.c == nil {
		return runner, nil
	}

	var err error
	runner.sink, err = prommetrics.NewPrometheusSinkFrom(prommetrics.PrometheusOpts{})
	if err != nil {
		return runner, err
	}

	handlerOpts := promhttp.HandlerOpts{
		ErrorLog: runner.log,
	}
	handler := promhttp.HandlerFor(prometheus.DefaultGatherer, handlerOpts)

	if runner.c.Host == "" {
		runner.c.Host = "localhost"
	}

	if runner.c.Host != "localhost" {
		runner.log.Warnf("Agent is now configured to accept remote network connections for Prometheus stats collection. Please ensure access to this port is tightly controlled")
	}

	runner.log.WithFields(logrus.Fields{
		"host": runner.c.Host,
		"port": runner.c.Port,
	}).Info("Starting prometheus exporter")

	runner.server = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", runner.c.Host, runner.c.Port),
		Handler:           handler,
		ReadHeaderTimeout: time.Second * 10,
	}

	if runner.c.TLS != nil {
		if err := runner.configureTLS(); err != nil {
			return runner, fmt.Errorf("failed to create TLS config for Prometheus: %w", err)
		}
	}

	return runner, nil
}

func (p *prometheusRunner) isConfigured() bool {
	return p.c != nil
}

func (p *prometheusRunner) sinks() []Sink {
	if !p.isConfigured() {
		return []Sink{}
	}

	return []Sink{p.sink}
}

func (p *prometheusRunner) run(ctx context.Context) error {
	if !p.isConfigured() {
		return nil
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		listener, err := net.Listen("tcp", p.server.Addr)
		if err == nil {
			err = p.serve(listener)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			p.log.Warnf("Prometheus listener stopped unexpectedly: %v", err)
		}
	})

	wg.Go(func() {
		<-ctx.Done()
		p.server.Close()
	})

	wg.Wait()
	return ctx.Err()
}

// serve owns the listener in every mode, including configuration errors.
func (p *prometheusRunner) serve(listener net.Listener) error {
	defer listener.Close()
	if p.ownedTLS != nil {
		// Never fall through to stock TLS or plaintext on an owned-config error.
		if p.server.TLSConfig != nil {
			return errors.New("Prometheus SPIFFE listener cannot use a mutable TLSConfig")
		}
		secured, err := p.ownedTLS.Listener(listener)
		if err != nil {
			return err
		}
		defer secured.Close()
		return p.server.Serve(secured)
	}
	if p.server.TLSConfig != nil {
		return p.server.ServeTLS(listener, "", "")
	}
	return p.server.Serve(listener)
}

func (p *prometheusRunner) requiresTypePrefix() bool {
	return false
}

func (p *prometheusRunner) configureTLS() error {
	if err := p.validateTLSConfig(); err != nil {
		return err
	}
	authorizedSPIFFEIDs, err := p.authorizedSPIFFEIDs()
	if err != nil {
		return err
	}

	// Apply mutable SPIRE preferences before the SDK takes its snapshot. The
	// owned configuration overrides authentication, version, KEM and session
	// settings with the strict profile; preferences cannot weaken that boundary.
	base := &tls.Config{}
	if err := tlspolicy.ApplyPolicy(base, p.tlsPolicy, tlspolicy.WithServerTLSConfig()); err != nil {
		return fmt.Errorf("failed to apply TLS policy for Prometheus: %w", err)
	}
	if p.c.TLS.UseSPIRESVID {
		p.ownedTLS = p.newSPIFFETLSConfig(authorizedSPIFFEIDs, base)
		return nil
	}

	certificate, err := tls.LoadX509KeyPair(p.c.TLS.CertFile, p.c.TLS.KeyFile)
	if err != nil {
		return err
	}
	if len(authorizedSPIFFEIDs) > 0 {
		p.ownedTLS = p.newSPIFFEWebTLSConfig(&certificate, authorizedSPIFFEIDs, base)
		return nil
	}

	// Preserve explicitly configured, non-SPIFFE file-certificate TLS. This is
	// a separate mode, never a fallback for an owned SPIFFE handshake failure.
	base.Certificates = []tls.Certificate{certificate}
	if p.c.TLS.ClientCAFile != "" {
		caCertPool, err := util.LoadCertPool(p.c.TLS.ClientCAFile)
		if err != nil {
			return err
		}
		base.ClientCAs = caCertPool
		base.ClientAuth = tls.RequireAndVerifyClientCert
	}
	p.server.TLSConfig = base
	return nil
}

func (p *prometheusRunner) validateTLSConfig() error {
	switch {
	case p.c.TLS.UseSPIRESVID && (p.c.TLS.CertFile != "" || p.c.TLS.KeyFile != ""):
		return errors.New("cert_file and key_file cannot be configured when use_spire_svid is enabled")
	case !p.c.TLS.UseSPIRESVID && (p.c.TLS.CertFile == "" || p.c.TLS.KeyFile == ""):
		return errors.New("cert_file and key_file must both be configured unless use_spire_svid is enabled")
	case len(p.c.TLS.AuthorizedSPIFFEIDs) > 0 && p.c.TLS.ClientCAFile != "":
		return errors.New("client_ca_file cannot be configured with authorized_spiffe_ids")
	case p.c.TLS.UseSPIRESVID && p.getX509SVID == nil:
		return errors.New("use_spire_svid requires access to the current SPIRE SVID")
	case len(p.c.TLS.AuthorizedSPIFFEIDs) > 0 && p.getX509BundleAuthorities == nil:
		return errors.New("authorized_spiffe_ids requires access to SPIRE trust bundles")
	default:
		return nil
	}
}

func (p *prometheusRunner) authorizedSPIFFEIDs() ([]spiffeid.ID, error) {
	authorizedIDs := make([]spiffeid.ID, 0, len(p.c.TLS.AuthorizedSPIFFEIDs))
	for _, idString := range p.c.TLS.AuthorizedSPIFFEIDs {
		id, err := spiffeid.FromString(idString)
		if err != nil {
			return nil, fmt.Errorf("invalid authorized SPIFFE ID %q: %w", idString, err)
		}
		authorizedIDs = append(authorizedIDs, id)
	}
	return authorizedIDs, nil
}

func (p *prometheusRunner) newSPIFFETLSConfig(authorizedSPIFFEIDs []spiffeid.ID, base *tls.Config) *tlsconfig.Config {
	svidSource := &telemetryX509SVIDSource{getter: p.getX509SVID}
	if len(authorizedSPIFFEIDs) > 0 {
		bundleSource := &telemetryBundleSource{getter: p.getX509BundleAuthorities}
		return tlsconfig.MTLSServerConfig(svidSource, bundleSource, tlsconfig.AuthorizeOneOf(authorizedSPIFFEIDs...), tlsconfig.WithBaseTLSConfig(base))
	}
	return tlsconfig.TLSServerConfig(svidSource, tlsconfig.WithBaseTLSConfig(base))
}

func (p *prometheusRunner) newSPIFFEWebTLSConfig(certificate *tls.Certificate, authorizedSPIFFEIDs []spiffeid.ID, base *tls.Config) *tlsconfig.Config {
	bundleSource := &telemetryBundleSource{getter: p.getX509BundleAuthorities}
	return tlsconfig.MTLSWebServerConfig(certificate, bundleSource, tlsconfig.AuthorizeOneOf(authorizedSPIFFEIDs...), tlsconfig.WithBaseTLSConfig(base))
}

type telemetryX509SVIDSource struct {
	getter func() (*x509svid.SVID, error)
}

func (s *telemetryX509SVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	return s.getter()
}

type telemetryBundleSource struct {
	getter func(spiffeid.TrustDomain) ([]*x509.Certificate, error)
}

func (s *telemetryBundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	authorities, err := s.getter(trustDomain)
	if err != nil {
		return nil, err
	}

	bundle := x509bundle.FromX509Authorities(trustDomain, authorities)
	return bundle.GetX509BundleForTrustDomain(trustDomain)
}
