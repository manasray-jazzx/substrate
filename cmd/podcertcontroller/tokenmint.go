// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/tokenbroker"
	"github.com/agent-substrate/substrate/internal/identitycert"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/proto/podcertbrokerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/client-go/kubernetes"
)

// brokerCertPollInterval/minBackoff/maxBackoff match cmd/podcertsidecar's own
// refresh-loop cadence, so every rotation-detection loop in the system runs
// on the same cadence.
const (
	brokerCertPollInterval = 60 * time.Second
	brokerCertMinBackoff   = 5 * time.Second
	brokerCertMaxBackoff   = 60 * time.Second
)

// startTokenBroker starts the TokenReview-authenticated PodCertificateBroker
// RPC listener in the background and returns once it is listening, or
// returns an error without starting anything.
//
// The listener's own serving certificate is minted directly from
// serviceDNSCAPool -- the same pool (and, via its ConfigMap mirror, the same
// trust bundle) already available to every caller -- so there is no
// bootstrap problem: podcertcontroller holds the CA material outright, it
// does not need a certificate issued to it by anything else. Unlike every
// other certificate in this system -- refreshed by a sidecar rewriting a
// file (cmd/podcertsidecar), or by re-reading one (ate-api-server's
// credbundle.Loader) -- this one is minted in-process and served straight
// from memory, so it needs its own refresh loop: a certificate installed
// once via tls.Config.Certificates and never touched again goes invalid
// identitycert.DefaultLifetime after startup and stays that way until the
// process restarts, wedging every consumer's podcert-sidecar-* cluster-wide,
// permanently, until someone notices and restarts this one pod -- found live
// (see docs/dev/eks-aks-workaround.md) when exactly that happened on a
// cluster that had been up for more than a day.
//
// Authentication is caller-side only: a caller has no certificate yet (that
// is the entire point of this RPC), so it authenticates via the bound token
// carried in the request payload instead of a client certificate. The server
// certificate below is what lets the caller trust it is really talking to
// podcertcontroller.
func startTokenBroker(ctx context.Context, listenAddress, servingDNSName, audience string, kc kubernetes.Interface, podIdentityCAPool, serviceDNSCAPool localca.Pool) error {
	servingCert := newRefreshingBrokerCert(serviceDNSCAPool, servingDNSName)
	if err := servingCert.mint(); err != nil {
		return fmt.Errorf("while minting PodCertificateBroker serving certificate: %w", err)
	}

	lis, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("while listening on %q: %w", listenAddress, err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		GetCertificate: servingCert.get,
		MinVersion:     tls.VersionTLS12,
	})))
	podcertbrokerpb.RegisterPodCertificateBrokerServer(srv, tokenbroker.NewServer(kc, tokenbroker.NewVerifier(kc, audience), podIdentityCAPool, serviceDNSCAPool))

	go servingCert.refreshLoop(ctx)
	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()
	go func() {
		if err := srv.Serve(lis); err != nil {
			slog.ErrorContext(ctx, "PodCertificateBroker listener stopped", slog.Any("err", err))
		}
	}()

	slog.InfoContext(ctx, "PodCertificateBroker listening", slog.String("address", listenAddress))
	return nil
}

// refreshingBrokerCert holds the PodCertificateBroker listener's own serving
// certificate and keeps it refreshed for as long as refreshLoop runs.
type refreshingBrokerCert struct {
	pool    localca.Pool
	dnsName string
	// lifetime overrides identitycert.DefaultLifetime when set; only tests
	// need this, to keep beginRefreshAt reachable without waiting out a real
	// 24h certificate.
	lifetime time.Duration

	mu       sync.RWMutex
	cert     *tls.Certificate
	notAfter time.Time
}

func newRefreshingBrokerCert(pool localca.Pool, dnsName string) *refreshingBrokerCert {
	return &refreshingBrokerCert{pool: pool, dnsName: dnsName}
}

// get implements tls.Config.GetCertificate.
func (b *refreshingBrokerCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.cert, nil
}

// mint signs a fresh certificate and installs it, replacing whatever was
// there before.
func (b *refreshingBrokerCert) mint() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("while generating key: %w", err)
	}

	notBefore, notAfter, _ := identitycert.Validity(b.lifetime)
	template := identitycert.ServiceDNSTemplate([]string{b.dnsName}, notBefore, notAfter)

	chainDER, err := b.pool.CreateCertificate(template, &key.PublicKey)
	if err != nil {
		return fmt.Errorf("while signing certificate: %w", err)
	}

	cert := tls.Certificate{Certificate: chainDER, PrivateKey: key}
	b.mu.Lock()
	b.cert = &cert
	b.notAfter = notAfter
	b.mu.Unlock()
	return nil
}

// refreshLoop re-mints the certificate for as long as ctx is not canceled,
// mirroring cmd/podcertsidecar's own mint-and-refresh loop cadence and
// backoff. The initial certificate is already installed by mint before this
// is started, so this only ever waits first.
func (b *refreshingBrokerCert) refreshLoop(ctx context.Context) {
	backoff := brokerCertMinBackoff
	for {
		b.mu.RLock()
		beginRefreshAt := b.notAfter.Add(-identitycert.RefreshHeadroom)
		b.mu.RUnlock()
		if !waitUntil(ctx, beginRefreshAt) {
			return
		}

		if err := b.mint(); err != nil {
			slog.ErrorContext(ctx, "PodCertificateBroker: failed to refresh serving certificate, retrying", slog.Any("err", err), slog.Duration("backoff", backoff))
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, brokerCertMaxBackoff)
			continue
		}
		backoff = brokerCertMinBackoff
		slog.InfoContext(ctx, "PodCertificateBroker: refreshed serving certificate")
	}
}

// waitUntil blocks until deadline or ctx is canceled, polling every
// brokerCertPollInterval rather than sleeping for the whole interval in one
// shot, so a shutdown signal is noticed promptly. Returns false if ctx was
// canceled first.
func waitUntil(ctx context.Context, deadline time.Time) bool {
	if !time.Now().Before(deadline) {
		return ctx.Err() == nil
	}

	ticker := time.NewTicker(brokerCertPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case now := <-ticker.C:
			if !now.Before(deadline) {
				return true
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
