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

// Package identitycert builds the podidentity.podcert.ate.dev/identity and
// servicedns.podcert.ate.dev/identity certificate templates, and signs and
// PEM-encodes the result. It holds the logic shared by every caller that can
// issue these two certificate types, whatever authenticated the caller: the
// PodCertificateRequest-based signers in podidentitysigner and
// servicednssigner, and the TokenReview-based broker for clusters where
// PodCertificateRequest is unavailable.
package identitycert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/substratex509"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// DefaultLifetime is the certificate lifetime used unless a shorter one is
// requested.
const DefaultLifetime = 24 * time.Hour

// RefreshHeadroom is how long before NotAfter a consumer should refresh.
const RefreshHeadroom = 30 * time.Minute

// notBeforeSkew backdates NotBefore to tolerate clock skew between the
// signer and whoever verifies the certificate first.
const notBeforeSkew = -2 * time.Minute

// Validity computes the NotBefore/NotAfter/BeginRefreshAt triple for a
// certificate. requestedLifetime clamps DefaultLifetime down (never up); a
// non-positive requestedLifetime is ignored.
func Validity(requestedLifetime time.Duration) (notBefore, notAfter, beginRefreshAt time.Time) {
	lifetime := DefaultLifetime
	if requestedLifetime > 0 && requestedLifetime < lifetime {
		lifetime = requestedLifetime
	}
	notBefore = time.Now().Add(notBeforeSkew)
	notAfter = notBefore.Add(lifetime)
	beginRefreshAt = notAfter.Add(-RefreshHeadroom)
	return notBefore, notAfter, beginRefreshAt
}

// PodIdentityTemplate builds the certificate template for a
// podidentity.podcert.ate.dev/identity certificate: a SPIFFE URI SAN plus the
// substratex509 PodIdentity extension. Every field of identity is mandatory
// -- see substratex509's validatePodIdentity -- so the caller must have
// resolved all of them (including NodeUID, which a Pod object alone does not
// carry) before calling this.
func PodIdentityTemplate(identity *substratex509.PodIdentity, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	spiffeURI := &url.URL{
		Scheme: "spiffe",
		Host:   "cluster.local",
		Path:   path.Join("ns", identity.Namespace, "sa", identity.ServiceAccountName),
	}

	template := &x509.Certificate{
		// Some golang certificate handling code assumes that if the parent and
		// template Subject fields compare equal, we are doing a self-signing
		// operation [1].
		//
		// I'm not sure if this is correct, but for defense in depth include
		// some random content in the subject.
		//
		// [1] https://cs.opensource.google/go/go/+/refs/tags/go1.27.0:src/crypto/x509/x509.go;l=1871
		Subject: pkix.Name{
			CommonName: rand.Text(),
		},
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		URIs:                  []*url.URL{spiffeURI},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// AuthorityKeyID is automatically set to the SubjectKeyID of the parent
		// certificate, as long as we are not self-signing a root.
	}

	if err := substratex509.AddPodIdentityToCertificate(identity, template); err != nil {
		return nil, fmt.Errorf("while adding pod identity to certificate: %w", err)
	}

	return template, nil
}

// ServiceDNSNames returns the DNS names, in "<service>.<namespace>.svc" form,
// of every Service in namespace that selects the pod named podName with UID
// podUID. Returns an error -- meant to be treated as transient/retryable, so
// a caller can wait for a Service to appear -- if the pod isn't (yet)
// selected by any Service, since a serving certificate with no DNS SANs is
// useless.
func ServiceDNSNames(ctx context.Context, kc kubernetes.Interface, namespace, podName string, podUID types.UID) ([]string, error) {
	// TODO: Switch from live reads to an indexer, and stop looping over every
	// Service -- maintain an index of pod to covering services instead.

	svcs, err := kc.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("while listing services: %w", err)
	}

	dnsNames := []string{}
	for _, svc := range svcs.Items {
		switch svc.Spec.Type {
		case corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort, corev1.ServiceTypeLoadBalancer:
			// ok
		default:
			// This service type doesn't select pods using a label selector.
			continue
		}

		if len(svc.Spec.Selector) == 0 {
			continue
		}

		matchedPods, err := kc.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector}),
		})
		if err != nil {
			return nil, fmt.Errorf("while selecting pods for service %q: %w", namespace+"/"+svc.ObjectMeta.Name, err)
		}

		for _, matchedPod := range matchedPods.Items {
			if matchedPod.ObjectMeta.Name == podName && matchedPod.ObjectMeta.UID == podUID {
				// TODO: I'm making some assumptions about the DNS names that
				// resolve to a given Service. I know at least one configuration
				// that I suspect doesn't match these assumptions --- GKE with
				// VPC-scoped Cloud DNS [1].
				//
				// [1] https://cloud.google.com/kubernetes-engine/docs/how-to/cloud-dns#vpc_scope_dns
				dnsNames = append(dnsNames, fmt.Sprintf("%s.%s.svc", svc.ObjectMeta.Name, namespace))
			}
		}
	}

	if len(dnsNames) == 0 {
		return nil, fmt.Errorf("pod %s/%s is not (yet) selected by any Service; refusing to issue a serving cert with no DNS SANs", namespace, podName)
	}

	return dnsNames, nil
}

// ServiceDNSTemplate builds the certificate template for a
// servicedns.podcert.ate.dev/identity certificate with the given DNS SANs.
func ServiceDNSTemplate(dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// AuthorityKeyID is automatically set to the SubjectKeyID of the parent
		// certificate.
	}
}

// SignAndEncode signs template for subjectPublicKey with pool and PEM-encodes
// the resulting certificate chain, leaf first.
func SignAndEncode(pool localca.Pool, template *x509.Certificate, subjectPublicKey crypto.PublicKey) (string, error) {
	chainDER, err := pool.CreateCertificate(template, subjectPublicKey)
	if err != nil {
		return "", fmt.Errorf("while signing certificate: %w", err)
	}

	chainPEM := &bytes.Buffer{}
	for _, certDER := range chainDER {
		if err := pem.Encode(chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
			return "", fmt.Errorf("while encoding certificate to PEM: %w", err)
		}
	}

	return chainPEM.String(), nil
}

// TrustBundlePEM PEM-encodes every trust anchor in pool, concatenated, in the
// form ClusterTrustBundle.Spec.TrustBundle (and its ConfigMap mirror) expect.
func TrustBundlePEM(pool localca.Pool) (string, error) {
	trustAnchors, err := pool.TrustAnchors()
	if err != nil {
		return "", fmt.Errorf("while retrieving CA pool trust anchors: %w", err)
	}

	buf := &bytes.Buffer{}
	for _, anchor := range trustAnchors {
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})
		_, _ = buf.Write(block)
	}

	return buf.String(), nil
}
