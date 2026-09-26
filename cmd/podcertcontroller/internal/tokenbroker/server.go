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

package tokenbroker

import (
	"context"
	"crypto"
	"log/slog"
	"time"

	"github.com/agent-substrate/substrate/internal/identitycert"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/proto/podcertbrokerpb"
	"github.com/agent-substrate/substrate/internal/substratex509"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Server implements podcertbrokerpb.PodCertificateBrokerServer, minting the
// same podidentity/servicedns certificates the PodCertificateRequest-based
// signers issue, for TokenReview-authenticated callers.
type Server struct {
	podcertbrokerpb.UnimplementedPodCertificateBrokerServer

	kc       kubernetes.Interface
	verifier *Verifier

	podIdentityCAPool localca.Pool
	serviceDNSCAPool  localca.Pool
}

// NewServer returns a Server that signs pod-identity certificates from
// podIdentityCAPool and service-DNS certificates from serviceDNSCAPool --
// the same pools the PodCertificateRequest-based signers use.
func NewServer(kc kubernetes.Interface, verifier *Verifier, podIdentityCAPool, serviceDNSCAPool localca.Pool) *Server {
	return &Server{
		kc:                kc,
		verifier:          verifier,
		podIdentityCAPool: podIdentityCAPool,
		serviceDNSCAPool:  serviceDNSCAPool,
	}
}

var _ podcertbrokerpb.PodCertificateBrokerServer = (*Server)(nil)

func (s *Server) MintPodCertificate(ctx context.Context, req *podcertbrokerpb.MintPodCertificateRequest) (*podcertbrokerpb.MintPodCertificateResponse, error) {
	identity, err := s.verifier.Verify(ctx, req.GetToken(), req.GetPodName(), req.GetPodUid())
	if err != nil {
		slog.WarnContext(ctx, "podcertbroker: rejecting caller", slog.Any("err", err))
		return nil, status.Error(codes.PermissionDenied, "caller identity could not be verified")
	}

	// Only the CSR's public key is ever used below -- any Subject/SAN fields
	// the caller populated are discarded along with the rest of the parsed
	// CSR. The issued certificate's identity comes entirely from identity,
	// established above from TokenReview plus a Pod lookup, never from the
	// CSR itself.
	csr, err := ParseAndVerifyCSR(req.GetCertificateSigningRequest())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid certificate signing request: %v", err)
	}

	notBefore, notAfter, _ := identitycert.Validity(0)

	var chainDER [][]byte
	switch req.GetPurpose() {
	case podcertbrokerpb.SignerPurpose_SIGNER_PURPOSE_POD_IDENTITY:
		chainDER, err = s.mintPodIdentity(ctx, identity, csr.PublicKey, notBefore, notAfter)
	case podcertbrokerpb.SignerPurpose_SIGNER_PURPOSE_SERVICE_DNS:
		chainDER, err = s.mintServiceDNS(ctx, identity, csr.PublicKey, notBefore, notAfter)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unrecognized signer purpose %v", req.GetPurpose())
	}
	if err != nil {
		return nil, err
	}

	return &podcertbrokerpb.MintPodCertificateResponse{CertificateChain: chainDER}, nil
}

// mintPodIdentity issues a podidentity.podcert.ate.dev/identity certificate.
// NodeUID -- required by substratex509's PodIdentity validation, and not
// obtainable from a Pod object alone -- comes from a Node lookup by the name
// the Pod lookup in Verify already resolved.
func (s *Server) mintPodIdentity(ctx context.Context, identity *CallerIdentity, subjectPublicKey crypto.PublicKey, notBefore, notAfter time.Time) ([][]byte, error) {
	if identity.NodeName == "" {
		return nil, status.Error(codes.FailedPrecondition, "caller's pod is not yet scheduled to a node")
	}
	node, err := s.kc.CoreV1().Nodes().Get(ctx, identity.NodeName, metav1.GetOptions{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "while resolving node identity: %v", err)
	}

	podIdentity := &substratex509.PodIdentity{
		Namespace:          identity.Namespace,
		ServiceAccountName: identity.ServiceAccountName,
		ServiceAccountUID:  identity.ServiceAccountUID,
		PodName:            identity.PodName,
		PodUID:             identity.PodUID,
		NodeName:           identity.NodeName,
		NodeUID:            string(node.UID),
	}
	template, err := identitycert.PodIdentityTemplate(podIdentity, notBefore, notAfter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	chainDER, err := s.podIdentityCAPool.CreateCertificate(template, subjectPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "while signing certificate: %v", err)
	}
	return chainDER, nil
}

// mintServiceDNS issues a servicedns.podcert.ate.dev/identity certificate,
// deriving its DNS SANs from the Services that select the caller's pod --
// never from the caller, who cannot supply DNS names for a servicedns cert.
func (s *Server) mintServiceDNS(ctx context.Context, identity *CallerIdentity, subjectPublicKey crypto.PublicKey, notBefore, notAfter time.Time) ([][]byte, error) {
	dnsNames, err := identitycert.ServiceDNSNames(ctx, s.kc, identity.Namespace, identity.PodName, types.UID(identity.PodUID))
	if err != nil {
		// Transient/retryable: the caller's pod may not be selected by its
		// Service yet. The sidecar's own retry loop is what retries this.
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	template := identitycert.ServiceDNSTemplate(dnsNames, notBefore, notAfter)

	chainDER, err := s.serviceDNSCAPool.CreateCertificate(template, subjectPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "while signing certificate: %v", err)
	}
	return chainDER, nil
}
