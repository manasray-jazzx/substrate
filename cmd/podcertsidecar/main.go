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

// Command podcertsidecar mints a podidentity.podcert.ate.dev/identity or
// servicedns.podcert.ate.dev/identity certificate from podcertcontroller's
// PodCertificateBroker RPC, and keeps it refreshed for as long as it runs.
//
// It is the counterpart, for clusters where PodCertificateRequest is
// unavailable, to the podCertificate projected volume kubelet otherwise
// provisions and rotates automatically: run as a native sidecar
// (initContainers entry with restartPolicy: Always) alongside every
// consumer that would otherwise use that volume source, writing the same
// credential-bundle.pem format at the same path those consumers already
// read via internal/credbundle, so they need no changes.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/agent-substrate/substrate/internal/credbundle"
	"github.com/agent-substrate/substrate/internal/identitycert"
	"github.com/agent-substrate/substrate/internal/proto/podcertbrokerpb"
	"github.com/agent-substrate/substrate/internal/version"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// pollInterval is how often the refresh loop wakes to check whether it's
// time to re-mint, matching internal/localca.RefreshingPool's own
// file-change-detection cadence so every rotation-detection loop in the
// system runs on the same cadence.
const pollInterval = 60 * time.Second

const minBackoff = 5 * time.Second
const maxBackoff = 60 * time.Second

var (
	purposeFlag = pflag.String(
		"purpose",
		"",
		`Which certificate to mint: "podidentity" or "servicedns".`,
	)
	brokerAddress = pflag.String(
		"broker-address",
		"",
		"host:port of podcertcontroller's PodCertificateBroker RPC.",
	)
	// The token's audience is scoped by the projected serviceAccountToken
	// volume this file comes from (its own audience: field), not by
	// anything this binary passes at request time -- podcertcontroller
	// checks the audience TokenReview reports for the token itself.
	tokenPath = pflag.String(
		"token-path",
		"",
		"Path to the bound ServiceAccount token, from a projected serviceAccountToken volume.",
	)
	trustBundlePath = pflag.String(
		"trust-bundle-path",
		"",
		"Path to the PEM trust bundle verifying the broker's serving certificate.",
	)
	credentialBundlePath = pflag.String(
		"credential-bundle-path",
		"",
		"Path to write the minted credential bundle to.",
	)
	podName = pflag.String("pod-name", "", "This pod's name, from the Downward API.")
	podUID  = pflag.String("pod-uid", "", "This pod's UID, from the Downward API.")

	showVersion = pflag.Bool("version", false, "Print version and exit.")
)

func main() {
	pflag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	purpose, err := parsePurpose(*purposeFlag)
	if err != nil {
		slog.Error("invalid --purpose", slog.Any("err", err))
		os.Exit(1)
	}
	if *brokerAddress == "" || *tokenPath == "" || *trustBundlePath == "" || *credentialBundlePath == "" || *podName == "" || *podUID == "" {
		slog.Error("--broker-address, --token-path, --trust-bundle-path, --credential-bundle-path, --pod-name, and --pod-uid are all required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := mintConfig{
		purpose:              purpose,
		brokerAddress:        *brokerAddress,
		tokenPath:            *tokenPath,
		trustBundlePath:      *trustBundlePath,
		credentialBundlePath: *credentialBundlePath,
		podName:              *podName,
		podUID:               *podUID,
	}

	backoff := minBackoff
	for ctx.Err() == nil {
		notAfter, err := mintOnce(ctx, cfg)
		if err != nil {
			slog.ErrorContext(ctx, "podcertsidecar: mint failed, retrying", slog.Any("err", err), slog.Duration("backoff", backoff))
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		backoff = minBackoff
		slog.InfoContext(ctx, "podcertsidecar: minted certificate", slog.Time("not_after", notAfter))
		if !waitUntilRefresh(ctx, notAfter.Add(-identitycert.RefreshHeadroom)) {
			return
		}
	}
}

func parsePurpose(s string) (podcertbrokerpb.SignerPurpose, error) {
	switch s {
	case "podidentity":
		return podcertbrokerpb.SignerPurpose_SIGNER_PURPOSE_POD_IDENTITY, nil
	case "servicedns":
		return podcertbrokerpb.SignerPurpose_SIGNER_PURPOSE_SERVICE_DNS, nil
	default:
		return podcertbrokerpb.SignerPurpose_SIGNER_PURPOSE_UNSPECIFIED, fmt.Errorf(`must be "podidentity" or "servicedns", got %q`, s)
	}
}

type mintConfig struct {
	purpose podcertbrokerpb.SignerPurpose

	brokerAddress string

	tokenPath            string
	trustBundlePath      string
	credentialBundlePath string

	podName string
	podUID  string
}

// mintOnce mints a fresh certificate and writes it to
// cfg.credentialBundlePath, returning its expiry for refresh scheduling. It
// generates a new key on every call, matching the CSR-per-mint pattern
// internal/atunnel's MintAteomCertificate already uses: the previous key is
// discarded along with the previous certificate.
func mintOnce(ctx context.Context, cfg mintConfig) (time.Time, error) {
	pool, err := credbundle.ParsePool(cfg.trustBundlePath)
	if err != nil {
		return time.Time{}, fmt.Errorf("while loading trust bundle: %w", err)
	}
	tokenBytes, err := os.ReadFile(cfg.tokenPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("while reading bound service account token: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return time.Time{}, fmt.Errorf("while generating key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return time.Time{}, fmt.Errorf("while creating certificate signing request: %w", err)
	}

	// A fresh connection per mint keeps this simple and matches how
	// infrequently minting actually happens (roughly once per cert
	// lifetime minus its refresh headroom); there is no long-lived
	// connection to keep alive.
	conn, err := grpc.NewClient(cfg.brokerAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})))
	if err != nil {
		return time.Time{}, fmt.Errorf("while dialing broker: %w", err)
	}
	defer conn.Close()

	resp, err := podcertbrokerpb.NewPodCertificateBrokerClient(conn).MintPodCertificate(ctx, &podcertbrokerpb.MintPodCertificateRequest{
		Token:                     strings.TrimSpace(string(tokenBytes)),
		Purpose:                   cfg.purpose,
		CertificateSigningRequest: csrDER,
		PodName:                   cfg.podName,
		PodUid:                    cfg.podUID,
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("while minting certificate: %w", err)
	}

	chain := resp.GetCertificateChain()
	if len(chain) == 0 {
		return time.Time{}, fmt.Errorf("broker returned no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("while parsing issued certificate: %w", err)
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		return time.Time{}, fmt.Errorf("issued certificate does not match the requested key")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !leaf.NotAfter.After(now) {
		return time.Time{}, fmt.Errorf("broker returned a certificate with an invalid lifetime")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return time.Time{}, fmt.Errorf("issued certificate cannot authenticate a TLS client")
	}

	if err := credbundle.Write(cfg.credentialBundlePath, key, chain); err != nil {
		return time.Time{}, fmt.Errorf("while writing credential bundle: %w", err)
	}

	return leaf.NotAfter, nil
}

// waitUntilRefresh blocks until beginRefreshAt or ctx is canceled, polling
// every pollInterval rather than sleeping for the whole interval in one
// shot, so a shutdown signal is noticed promptly. Returns false if ctx was
// canceled first.
func waitUntilRefresh(ctx context.Context, beginRefreshAt time.Time) bool {
	if !time.Now().Before(beginRefreshAt) {
		return ctx.Err() == nil
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case now := <-ticker.C:
			if !now.Before(beginRefreshAt) {
				return true
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
