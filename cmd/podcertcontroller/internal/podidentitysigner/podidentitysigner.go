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

package podidentitysigner

import (
	"context"
	"fmt"
	"time"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/identitycert"
	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/podcertificate"
	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/signercontroller"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/substratex509"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

const Name = "podidentity.podcert.ate.dev/identity"
const CTBPrefix = "podidentity.podcert.ate.dev:identity:"

type Impl struct {
	kc     kubernetes.Interface
	caPool localca.Pool
}

func NewImpl(kc kubernetes.Interface, caPool localca.Pool) *Impl {
	return &Impl{
		kc:     kc,
		caPool: caPool,
	}
}

var _ signercontroller.SignerImpl = (*Impl)(nil)

func (h *Impl) SignerName() string {
	return Name
}

func (h *Impl) DesiredClusterTrustBundles() ([]*certsv1beta1.ClusterTrustBundle, error) {
	name := CTBPrefix + "primary-bundle"

	trustBundle, err := identitycert.TrustBundlePEM(h.caPool)
	if err != nil {
		return nil, err
	}

	wantCTB := &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"podcert.ate.dev/canarying": "live",
			},
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  Name,
			TrustBundle: trustBundle,
		},
	}

	return []*certsv1beta1.ClusterTrustBundle{
		wantCTB,
	}, nil
}

func (h *Impl) MakeCert(ctx context.Context, pcr *certsv1beta1.PodCertificateRequest) error {
	// Fetch the pod to get its ServiceAccount
	pod, err := h.kc.CoreV1().Pods(pcr.ObjectMeta.Namespace).Get(ctx, pcr.Spec.PodName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("while getting pod %s/%s: %w", pcr.ObjectMeta.Namespace, pcr.Spec.PodName, err)
	}

	if pod.ObjectMeta.UID != pcr.Spec.PodUID {
		return fmt.Errorf("pod UID mismatch: expected %s, got %s", pcr.Spec.PodUID, pod.ObjectMeta.UID)
	}

	subjectPublicKey, err := podcertificate.PublicKey(pcr)
	if err != nil {
		return err
	}

	requestedLifetime := time.Duration(*pcr.Spec.MaxExpirationSeconds) * time.Second
	notBefore, notAfter, beginRefreshAt := identitycert.Validity(requestedLifetime)

	// Fields are sourced from the PCR spec (attested by kube-apiserver) rather
	// than the Pod object, which lacks the ServiceAccount and Node UIDs.
	podIdentity := &substratex509.PodIdentity{
		Namespace:          pcr.ObjectMeta.Namespace,
		ServiceAccountName: pcr.Spec.ServiceAccountName,
		ServiceAccountUID:  string(pcr.Spec.ServiceAccountUID),
		PodName:            pcr.Spec.PodName,
		PodUID:             string(pcr.Spec.PodUID),
		NodeName:           string(pcr.Spec.NodeName),
		NodeUID:            string(pcr.Spec.NodeUID),
	}
	template, err := identitycert.PodIdentityTemplate(podIdentity, notBefore, notAfter)
	if err != nil {
		return err
	}

	chainPEM, err := identitycert.SignAndEncode(h.caPool, template, subjectPublicKey)
	if err != nil {
		return err
	}

	pcr = pcr.DeepCopy()
	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               certsv1beta1.PodCertificateRequestConditionTypeIssued,
			Status:             metav1.ConditionTrue,
			Reason:             "Reason",
			Message:            "Issued",
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
	}
	pcr.Status.CertificateChain = chainPEM
	pcr.Status.NotBefore = ptr.To(metav1.NewTime(notBefore))
	pcr.Status.BeginRefreshAt = ptr.To(metav1.NewTime(beginRefreshAt))
	pcr.Status.NotAfter = ptr.To(metav1.NewTime(notAfter))

	_, err = h.kc.CertificatesV1beta1().PodCertificateRequests(pcr.ObjectMeta.Namespace).UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("while updating PodCertificateRequest: %w", err)
	}

	return nil
}
