package platform

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

const (
	MonitoringHealthy             = "healthy"
	MonitoringSerialMismatch      = "serial_mismatch"
	MonitoringCertificateExpiring = "certificate_expiring"
	MonitoringCertificateExpired  = "certificate_expired"
	MonitoringTLSUnreachable      = "tls_unreachable"
	MonitoringHostnameMismatch    = "hostname_mismatch"
)

// MonitoringState is the latest observation, not an instruction to deploy.
// An empty status means the target has never been probed.
type MonitoringState struct {
	Status         string    `json:"status"`
	ExpectedSerial string    `json:"expected_serial,omitempty"`
	OnlineSerial   string    `json:"online_serial,omitempty"`
	CheckedAt      time.Time `json:"checked_at"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	LastError      string    `json:"last_error,omitempty"`
}

type MonitoringOptions struct {
	Timeout        time.Duration
	ExpiringBefore time.Duration
}

func (o MonitoringOptions) validate() error {
	if o.Timeout <= 0 || o.ExpiringBefore < 0 {
		return fmt.Errorf("monitoring timeout must be positive and expiry window non-negative")
	}
	return nil
}

// ProbeDeploymentTarget observes a fresh TLS handshake. Verification is performed
// explicitly so expired and wrong-host certificates can still be inspected.
// This is an identity/expiry monitor; it does not certify CA trust or revocation.
func (s *Service) ProbeDeploymentTarget(ctx context.Context, id string, options MonitoringOptions) (MonitoringState, error) {
	if err := options.validate(); err != nil {
		return MonitoringState{}, err
	}
	target, err := s.GetDeploymentTarget(id)
	if err != nil {
		return MonitoringState{}, err
	}
	if !target.Enabled {
		return MonitoringState{}, fmt.Errorf("deployment target %q is disabled", id)
	}
	state := MonitoringState{CheckedAt: time.Now().UTC()}
	probeCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         target.Domain,
		InsecureSkipVerify: true, // Observation only; hostname and expiry checked below.
	}}
	conn, probeErr := dialer.DialContext(probeCtx, "tcp", target.Address)
	if ctx.Err() != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return MonitoringState{}, ctx.Err()
	}
	state.CheckedAt = time.Now().UTC()
	// Resolve current certificate after the handshake, allowing concurrent renewal.
	instance, err := s.DomainCertificateInstance(target.Domain)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		return MonitoringState{}, err
	}
	if instance.CurrentCertificate != nil {
		state.ExpectedSerial = instance.CurrentCertificate.SerialNumber
	}
	if probeErr != nil {
		state.Status = MonitoringTLSUnreachable
		state.LastError = probeErr.Error()
	} else {
		certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if len(certs) == 0 {
			state.Status = MonitoringTLSUnreachable
			state.LastError = "TLS peer returned no certificate"
		} else {
			cert := certs[0]
			state.OnlineSerial = CertificateSerialHex(cert)
			state.NotBefore, state.NotAfter = cert.NotBefore, cert.NotAfter
			switch {
			case !state.CheckedAt.Before(cert.NotAfter):
				state.Status = MonitoringCertificateExpired
			case cert.VerifyHostname(target.Domain) != nil:
				state.Status = MonitoringHostnameMismatch
				state.LastError = cert.VerifyHostname(target.Domain).Error()
			case state.CheckedAt.Before(cert.NotBefore):
				state.Status = MonitoringSerialMismatch
				state.LastError = "online certificate is not yet valid"
			case state.ExpectedSerial == "" || state.OnlineSerial != state.ExpectedSerial:
				state.Status = MonitoringSerialMismatch
				if state.ExpectedSerial == "" {
					state.LastError = "domain has no active current certificate"
				}
			case !cert.NotAfter.After(state.CheckedAt.Add(options.ExpiringBefore)):
				state.Status = MonitoringCertificateExpiring
			default:
				state.Status = MonitoringHealthy
			}
		}
	}

	s.mu.Lock()
	target = s.deploymentTargets[id]
	previous := target.Monitoring
	// Concurrent probes cannot overwrite a newer observation.
	if previous.CheckedAt.After(state.CheckedAt) {
		s.mu.Unlock()
		return previous, nil
	}
	if s.deploymentTargetRepository == nil {
		s.mu.Unlock()
		return MonitoringState{}, fmt.Errorf("deployment target repository is not configured")
	}
	target.Monitoring = state
	if err := s.deploymentTargetRepository.Save(target); err != nil {
		s.mu.Unlock()
		return MonitoringState{}, err
	}
	s.deploymentTargets[id] = target
	s.mu.Unlock()

	if err := s.RecordMonitoringTransition(target, previous, state); err != nil {
		return state, fmt.Errorf("record monitoring transition: %w", err)
	}
	return state, nil
}

type MonitoringResult struct {
	States         map[string]MonitoringState `json:"states"`
	Errors         map[string]string          `json:"errors"`
	SkippedTargets []string                   `json:"skipped_targets"`
}

func (s *Service) RunMonitoringScan(ctx context.Context, options MonitoringOptions) (MonitoringResult, error) {
	result := MonitoringResult{States: make(map[string]MonitoringState), Errors: make(map[string]string), SkippedTargets: []string{}}
	if err := options.validate(); err != nil {
		return result, err
	}
	for _, target := range s.DeploymentTargets("") {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !target.Enabled {
			result.SkippedTargets = append(result.SkippedTargets, target.ID)
			continue
		}
		state, err := s.ProbeDeploymentTarget(ctx, target.ID, options)
		if err != nil {
			result.Errors[target.ID] = err.Error()
			continue
		}
		result.States[target.ID] = state
	}
	return result, ctx.Err()
}

// RunMonitoring probes immediately, then periodically, until cancellation.
// Non-positive intervals disable periodic monitoring.
func (s *Service) RunMonitoring(ctx context.Context, interval time.Duration, options MonitoringOptions, report func(error)) {
	if interval <= 0 {
		return
	}
	run := func() {
		result, err := s.RunMonitoringScan(ctx, options)
		if report != nil {
			if err != nil {
				report(err)
			}
			for id, message := range result.Errors {
				report(fmt.Errorf("target %s: %s", id, message))
			}
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
