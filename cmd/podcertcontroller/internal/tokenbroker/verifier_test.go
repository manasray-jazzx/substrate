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
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const testAudience = "podcertcontroller.ate.dev"

// newFakeClientWithTokenReview returns a fake clientset seeded with objects
// (e.g. Pods, Nodes) whose TokenReviews().Create always returns review,
// regardless of the token presented -- the fake clientset's default object
// tracker has no notion of actually validating a bearer token.
func newFakeClientWithTokenReview(t *testing.T, review *authenticationv1.TokenReview, objects ...runtime.Object) *fake.Clientset {
	t.Helper()
	kc := fake.NewSimpleClientset(objects...)
	kc.PrependReactor("create", "tokenreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, review, nil
	})
	return kc
}

func authenticatedReview(namespace, serviceAccount, serviceAccountUID string, audiences []string, extra map[string]authenticationv1.ExtraValue) *authenticationv1.TokenReview {
	return &authenticationv1.TokenReview{
		Status: authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1.UserInfo{
				Username: "system:serviceaccount:" + namespace + ":" + serviceAccount,
				UID:      serviceAccountUID,
				Extra:    extra,
			},
			Audiences: audiences,
		},
	}
}

func testPod(namespace, name, uid, serviceAccount, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uid)},
		Spec:       corev1.PodSpec{ServiceAccountName: serviceAccount, NodeName: node},
	}
}

func TestVerifySucceeds(t *testing.T) {
	review := authenticatedReview("ns", "sa", "sa-uid", []string{testAudience}, nil)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "pod-uid", "sa", "node-1"))

	identity, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	want := &CallerIdentity{Namespace: "ns", ServiceAccountName: "sa", ServiceAccountUID: "sa-uid", PodName: "pod", PodUID: "pod-uid", NodeName: "node-1"}
	if *identity != *want {
		t.Fatalf("Verify() identity = %+v, want %+v", identity, want)
	}
}

func TestVerifyRejectsUnauthenticated(t *testing.T) {
	review := &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{Authenticated: false}}
	kc := newFakeClientWithTokenReview(t, review)

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error for an unauthenticated token")
	}
}

func TestVerifyRejectsEmptyAudienceIntersection(t *testing.T) {
	// Per TokenReviewStatus.Audiences' doc comment, an empty intersection
	// with Authenticated=true means the token carried no audience
	// restriction and was checked against the apiserver's default audience
	// instead -- never actually scoped to testAudience.
	review := authenticatedReview("ns", "sa", "sa-uid", nil, nil)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "pod-uid", "sa", "node-1"))

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error for an empty audience intersection")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	review := authenticatedReview("ns", "sa", "sa-uid", []string{"someone-else.example.com"}, nil)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "pod-uid", "sa", "node-1"))

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error for a token scoped to a different audience")
	}
}

func TestVerifyRejectsNonServiceAccountUsername(t *testing.T) {
	review := &authenticationv1.TokenReview{
		Status: authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User:          authenticationv1.UserInfo{Username: "someone@example.com"},
			Audiences:     []string{testAudience},
		},
	}
	kc := newFakeClientWithTokenReview(t, review)

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error for a non-ServiceAccount username")
	}
}

func TestVerifyRejectsPodServiceAccountMismatch(t *testing.T) {
	review := authenticatedReview("ns", "sa", "sa-uid", []string{testAudience}, nil)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "pod-uid", "different-sa", "node-1"))

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error when the pod does not run as the token's service account")
	}
}

func TestVerifyRejectsClaimedUIDMismatch(t *testing.T) {
	review := authenticatedReview("ns", "sa", "sa-uid", []string{testAudience}, nil)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "actual-uid", "sa", "node-1"))

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "claimed-different-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error when the claimed pod UID does not match the pod's actual UID")
	}
}

func TestVerifyRejectsMissingPod(t *testing.T) {
	review := authenticatedReview("ns", "sa", "sa-uid", []string{testAudience}, nil)
	kc := newFakeClientWithTokenReview(t, review) // no pod seeded

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error when the claimed pod does not exist")
	}
}

func TestVerifySucceedsWithAbsentExtras(t *testing.T) {
	review := authenticatedReview("ns", "sa", "sa-uid", []string{testAudience}, nil)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "pod-uid", "sa", "node-1"))

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err != nil {
		t.Fatalf("Verify() error = %v, want success when the token carries no bound-object extras", err)
	}
}

func TestVerifySucceedsWithMatchingExtras(t *testing.T) {
	extra := map[string]authenticationv1.ExtraValue{
		podNameExtraKey:  {"pod"},
		podUIDExtraKey:   {"pod-uid"},
		nodeNameExtraKey: {"node-1"},
	}
	review := authenticatedReview("ns", "sa", "sa-uid", []string{testAudience}, extra)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "pod-uid", "sa", "node-1"))

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err != nil {
		t.Fatalf("Verify() error = %v, want success when the token's bound-object extras match", err)
	}
}

func TestVerifyRejectsConflictingPodNameExtra(t *testing.T) {
	extra := map[string]authenticationv1.ExtraValue{podNameExtraKey: {"a-different-pod"}}
	review := authenticatedReview("ns", "sa", "sa-uid", []string{testAudience}, extra)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "pod-uid", "sa", "node-1"))

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error when the token's bound pod name conflicts with the claimed pod name")
	}
}

func TestVerifyRejectsConflictingPodUIDExtra(t *testing.T) {
	extra := map[string]authenticationv1.ExtraValue{podUIDExtraKey: {"a-different-uid"}}
	review := authenticatedReview("ns", "sa", "sa-uid", []string{testAudience}, extra)
	kc := newFakeClientWithTokenReview(t, review, testPod("ns", "pod", "pod-uid", "sa", "node-1"))

	if _, err := NewVerifier(kc, testAudience).Verify(context.Background(), "tok", "pod", "pod-uid"); err == nil {
		t.Fatalf("Verify() error = nil, want error when the token's bound pod UID conflicts with the claimed pod UID")
	}
}
