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
	"crypto/x509"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/localca"
)

// silenceLogs redirects the default slog logger to discard output for the
// duration of the calling test, restoring it on cleanup.
func silenceLogs(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

func testPool(t *testing.T) *localca.ConcretePool {
	t.Helper()
	ca, err := localca.GenerateCA("servicedns-test-ca", localca.KeyTypeECDSAP256, 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	return &localca.ConcretePool{CAs: []*localca.CA{ca}}
}

func TestRefreshingBrokerCertMintInstallsUsableCertificate(t *testing.T) {
	pool := testPool(t)
	b := newRefreshingBrokerCert(pool, "podcertificate-controller.podcertificate-controller-system.svc")

	if _, err := b.get(nil); err != nil {
		t.Fatalf("get before mint: %v", err)
	}
	if cert, _ := b.get(nil); cert != nil {
		t.Fatalf("get before mint = %+v, want nil (no certificate minted yet)", cert)
	}

	if err := b.mint(); err != nil {
		t.Fatalf("mint: %v", err)
	}

	cert, err := b.get(nil)
	if err != nil {
		t.Fatalf("get after mint: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("get after mint returned no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got, want := leaf.DNSNames, []string{"podcertificate-controller.podcertificate-controller-system.svc"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("leaf DNSNames = %v, want %v", got, want)
	}

	roots, err := pool.TrustAnchors()
	if err != nil {
		t.Fatalf("trust anchors: %v", err)
	}
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: rootPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("minted leaf does not verify against the pool's trust anchors: %v", err)
	}
}

// TestRefreshingBrokerCertMintReplacesThePreviousCertificate is the direct
// regression test for the bug this type fixes: before it existed, the
// broker's serving certificate was installed once via tls.Config.Certificates
// and never touched again, so it went permanently invalid
// identitycert.DefaultLifetime after startup. mint must be callable
// repeatedly and each call must actually replace what get returns.
func TestRefreshingBrokerCertMintReplacesThePreviousCertificate(t *testing.T) {
	pool := testPool(t)
	b := newRefreshingBrokerCert(pool, "podcertificate-controller.podcertificate-controller-system.svc")

	if err := b.mint(); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	first, _ := b.get(nil)

	if err := b.mint(); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	second, _ := b.get(nil)

	if string(first.Certificate[0]) == string(second.Certificate[0]) {
		t.Fatal("second mint did not replace the certificate get returns")
	}
}

// TestRefreshingBrokerCertRefreshLoopKeepsMinting drives refreshLoop with a
// lifetime short enough that beginRefreshAt is already in the past
// immediately after every mint, so the loop re-mints on every iteration
// without waiting out a real identitycert.DefaultLifetime (24h) or
// identitycert.RefreshHeadroom (30m). This is the loop-level counterpart to
// the mint-level regression test above: it proves refreshLoop actually
// drives repeated mints rather than minting once and returning.
func TestRefreshingBrokerCertRefreshLoopKeepsMinting(t *testing.T) {
	// A lifetime this short leaves beginRefreshAt (notAfter minus the fixed
	// 30-minute identitycert.RefreshHeadroom) in the past from the moment
	// each certificate is minted, so refreshLoop spins as fast as the CPU
	// allows rather than pacing itself -- expected only because of the
	// artificially short lifetime below, not a real startup condition, but
	// noisy without this.
	silenceLogs(t)

	pool := testPool(t)
	b := &refreshingBrokerCert{
		pool:     pool,
		dnsName:  "podcertificate-controller.podcertificate-controller-system.svc",
		lifetime: time.Millisecond,
	}
	if err := b.mint(); err != nil {
		t.Fatalf("initial mint: %v", err)
	}
	first, _ := b.get(nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.refreshLoop(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if cert, _ := b.get(nil); string(cert.Certificate[0]) != string(first.Certificate[0]) {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("refreshLoop never replaced the initial certificate")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refreshLoop did not stop after its context was canceled")
	}
}

func TestWaitUntilReturnsImmediatelyForAPastDeadline(t *testing.T) {
	if !waitUntil(context.Background(), time.Now().Add(-time.Hour)) {
		t.Error("waitUntil(past deadline) = false, want true")
	}
}

func TestWaitUntilReturnsFalseForACanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitUntil(ctx, time.Now().Add(time.Hour)) {
		t.Error("waitUntil(canceled ctx) = true, want false")
	}
}

func TestSleepCtxReturnsFalseForACanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, time.Hour) {
		t.Error("sleepCtx(canceled ctx) = true, want false")
	}
}

func TestSleepCtxReturnsTrueAfterItElapses(t *testing.T) {
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Error("sleepCtx(elapsed) = false, want true")
	}
}
