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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func generateCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create certificate signing request: %v", err)
	}
	return der
}

func TestParseAndVerifyCSRAcceptsValidCSR(t *testing.T) {
	der := generateCSR(t)

	csr, err := ParseAndVerifyCSR(der)
	if err != nil {
		t.Fatalf("ParseAndVerifyCSR() error = %v", err)
	}
	if csr.PublicKey == nil {
		t.Fatalf("ParseAndVerifyCSR() returned a CSR with a nil public key")
	}
}

func TestParseAndVerifyCSRRejectsUnparseableDER(t *testing.T) {
	if _, err := ParseAndVerifyCSR([]byte("not a certificate signing request")); err == nil {
		t.Fatalf("ParseAndVerifyCSR() error = nil, want error for unparseable input")
	}
}

func TestParseAndVerifyCSRRejectsInvalidSignature(t *testing.T) {
	der := generateCSR(t)

	// The CSR's signature is the trailing content of its outer BIT STRING.
	// Flipping the final byte corrupts the signature bytes while leaving the
	// ASN.1 length prefixes -- and so the overall structure -- intact, so
	// this must fail signature verification without failing to parse.
	corrupted := append([]byte(nil), der...)
	corrupted[len(corrupted)-1] ^= 0xFF

	csr, err := ParseAndVerifyCSR(corrupted)
	if err == nil {
		t.Fatalf("ParseAndVerifyCSR() error = nil, want error for a CSR with an invalid signature (parsed public key: %v)", csr.PublicKey)
	}
}
