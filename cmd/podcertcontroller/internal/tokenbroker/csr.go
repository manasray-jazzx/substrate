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
	"crypto/x509"
	"fmt"
)

// ParseAndVerifyCSR parses a DER-encoded PKCS#10 certificate signing request
// and verifies its self-signature. Unlike podcertificate.PublicKey -- which
// only ever parses kubelet's own synthetic stub CSRs, and has no signature
// check -- this must guard against an arbitrary, untrusted, client-submitted
// CSR: a forged or corrupted request must not reach certificate issuance.
//
// Only the returned CSR's PublicKey should ever be used to build an issued
// certificate. Any Subject or SAN fields the caller populated must be
// ignored -- the issued certificate's identity comes entirely from the
// caller's authenticated CallerIdentity, never from the CSR.
func ParseAndVerifyCSR(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("while parsing certificate signing request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate signing request has an invalid signature: %w", err)
	}
	return csr, nil
}
