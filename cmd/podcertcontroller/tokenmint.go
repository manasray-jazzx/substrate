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

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/identitycert"
	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/tokenbroker"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/proto/podcertbrokerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/client-go/kubernetes"
)

// startTokenBroker starts the TokenReview-authenticated PodCertificateBroker
// RPC listener in the background and returns once it is listening, or
// returns an error without starting anything.
//
// The listener's own serving certificate is minted directly from
// serviceDNSCAPool -- the same pool (and, via its ConfigMap mirror, the same
// trust bundle) already available to every caller -- so there is no
// bootstrap problem: podcertcontroller holds the CA material outright, it
// does not need a certificate issued to it by anything else.
//
// Authentication is caller-side only: a caller has no certificate yet (that
// is the entire point of this RPC), so it authenticates via the bound token
// carried in the request payload instead of a client certificate. The server
// certificate below is what lets the caller trust it is really talking to
// podcertcontroller.
func startTokenBroker(ctx context.Context, listenAddress, servingDNSName, audience string, kc kubernetes.Interface, podIdentityCAPool, serviceDNSCAPool localca.Pool) error {
	servingCert, err := mintBrokerServingCert(serviceDNSCAPool, servingDNSName)
	if err != nil {
		return fmt.Errorf("while minting PodCertificateBroker serving certificate: %w", err)
	}

	lis, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("while listening on %q: %w", listenAddress, err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{servingCert},
		MinVersion:   tls.VersionTLS12,
	})))
	podcertbrokerpb.RegisterPodCertificateBrokerServer(srv, tokenbroker.NewServer(kc, tokenbroker.NewVerifier(kc, audience), podIdentityCAPool, serviceDNSCAPool))

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

func mintBrokerServingCert(pool localca.Pool, dnsName string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("while generating key: %w", err)
	}

	notBefore, notAfter, _ := identitycert.Validity(0)
	template := identitycert.ServiceDNSTemplate([]string{dnsName}, notBefore, notAfter)

	chainDER, err := pool.CreateCertificate(template, &key.PublicKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("while signing certificate: %w", err)
	}

	return tls.Certificate{Certificate: chainDER, PrivateKey: key}, nil
}
