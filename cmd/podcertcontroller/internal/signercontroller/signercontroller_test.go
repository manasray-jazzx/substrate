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

package signercontroller

import (
	"context"
	"testing"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
)

// alwaysAssigned is a Hasher that always claims every item for this replica.
type alwaysAssigned struct{}

func (alwaysAssigned) AssignedToThisReplica(context.Context, string) bool { return true }

// stubSignerImpl is a SignerImpl whose only job is to report a single
// desired ClusterTrustBundle. MakeCert is never exercised by these tests.
type stubSignerImpl struct {
	name string
	ctb  *certsv1beta1.ClusterTrustBundle
}

func (s *stubSignerImpl) SignerName() string { return s.name }

func (s *stubSignerImpl) DesiredClusterTrustBundles() ([]*certsv1beta1.ClusterTrustBundle, error) {
	return []*certsv1beta1.ClusterTrustBundle{s.ctb}, nil
}

func (s *stubSignerImpl) MakeCert(context.Context, *certsv1beta1.PodCertificateRequest) error {
	return nil
}

func testCTB(name, trustBundle string) *certsv1beta1.ClusterTrustBundle {
	return &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"podcert.ate.dev/canarying": "live"}},
		Spec:       certsv1beta1.ClusterTrustBundleSpec{SignerName: "example.com/signer", TrustBundle: trustBundle},
	}
}

func TestRunTrustBundlePublisherDoesNotDependOnRun(t *testing.T) {
	// This is the regression test for the bug this package's design doc
	// describes: ensureBundles used to run only after Run's
	// cache.WaitForCacheSync succeeded, which never happens on a cluster
	// where PodCertificateRequest is unavailable. RunTrustBundlePublisher
	// must make progress on its own, with Run never called at all.
	ctb := testCTB("example.com:signer:primary-bundle", "trust-bundle-pem-content")
	kc := fake.NewSimpleClientset()
	handler := &stubSignerImpl{name: "example.com/signer", ctb: ctb}
	c := New(clock.RealClock{}, handler, kc, alwaysAssigned{}, "")

	c.ensureBundles(context.Background())

	got, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(context.Background(), ctb.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get(ClusterTrustBundle) after ensureBundles() error = %v", err)
	}
	if got.Spec.TrustBundle != ctb.Spec.TrustBundle {
		t.Fatalf("ClusterTrustBundle content = %q, want %q", got.Spec.TrustBundle, ctb.Spec.TrustBundle)
	}
}

func TestEnsureBundlesMirrorsToConfigMapWhenConfigured(t *testing.T) {
	ctb := testCTB("example.com:signer:primary-bundle", "trust-bundle-pem-content")
	kc := fake.NewSimpleClientset()
	handler := &stubSignerImpl{name: "example.com/signer", ctb: ctb}
	c := New(clock.RealClock{}, handler, kc, alwaysAssigned{}, "ate-system")

	c.ensureBundles(context.Background())

	wantName := "example.com-signer-primary-bundle"
	cm, err := kc.CoreV1().ConfigMaps("ate-system").Get(context.Background(), wantName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get(ConfigMap) after ensureBundles() error = %v", err)
	}
	if got := cm.Data["trust-bundle.pem"]; got != ctb.Spec.TrustBundle {
		t.Fatalf("ConfigMap data[trust-bundle.pem] = %q, want %q", got, ctb.Spec.TrustBundle)
	}
}

func TestEnsureBundlesSkipsConfigMapMirrorWhenNamespaceUnset(t *testing.T) {
	ctb := testCTB("example.com:signer:primary-bundle", "trust-bundle-pem-content")
	kc := fake.NewSimpleClientset()
	handler := &stubSignerImpl{name: "example.com/signer", ctb: ctb}
	c := New(clock.RealClock{}, handler, kc, alwaysAssigned{}, "")

	c.ensureBundles(context.Background())

	list, err := kc.CoreV1().ConfigMaps("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List(ConfigMap) error = %v", err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("ConfigMaps created = %d, want 0 when the mirror namespace is unset", len(list.Items))
	}
}

func TestEnsureBundlesWritesConfigMapMirrorEvenWhenClusterTrustBundleAPIFails(t *testing.T) {
	// The two writes are independent: a cluster missing the
	// ClusterTrustBundle API entirely must still get a working ConfigMap
	// mirror.
	ctb := testCTB("example.com:signer:primary-bundle", "trust-bundle-pem-content")
	kc := fake.NewSimpleClientset()
	kc.PrependReactor("*", "clustertrustbundles", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errNotRegistered
	})
	handler := &stubSignerImpl{name: "example.com/signer", ctb: ctb}
	c := New(clock.RealClock{}, handler, kc, alwaysAssigned{}, "ate-system")

	c.ensureBundles(context.Background())

	cm, err := kc.CoreV1().ConfigMaps("ate-system").Get(context.Background(), "example.com-signer-primary-bundle", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get(ConfigMap) after ensureBundles() error = %v, want the mirror to succeed despite the ClusterTrustBundle API failing", err)
	}
	if got := cm.Data["trust-bundle.pem"]; got != ctb.Spec.TrustBundle {
		t.Fatalf("ConfigMap data[trust-bundle.pem] = %q, want %q", got, ctb.Spec.TrustBundle)
	}
}

func TestEnsureBundlesSkipsInactiveReplica(t *testing.T) {
	ctb := testCTB("example.com:signer:primary-bundle", "trust-bundle-pem-content")
	kc := fake.NewSimpleClientset()
	handler := &stubSignerImpl{name: "example.com/signer", ctb: ctb}
	c := New(clock.RealClock{}, handler, kc, neverAssigned{}, "ate-system")

	c.ensureBundles(context.Background())

	list, err := kc.CoreV1().ConfigMaps("ate-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List(ConfigMap) error = %v", err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("ConfigMaps created = %d, want 0 when this replica is not assigned the trust-bundle maintenance work", len(list.Items))
	}
}

type neverAssigned struct{}

func (neverAssigned) AssignedToThisReplica(context.Context, string) bool { return false }

type stubError string

func (e stubError) Error() string { return string(e) }

const errNotRegistered stubError = "the server could not find the requested resource"
