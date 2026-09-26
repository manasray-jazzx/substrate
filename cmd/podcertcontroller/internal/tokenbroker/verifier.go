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

// Package tokenbroker authenticates a MintPodCertificate caller from a bound
// ServiceAccount token instead of a PodCertificateRequest, for clusters that
// do not have that Kubernetes API available (its ClusterTrustBundle /
// PodCertificateRequest feature gates are not exposed on a managed control
// plane such as EKS or AKS).
//
// This is a materially weaker identity binding than PodCertificateRequest's:
// a PodCertificateRequest's PodName/PodUID/NodeName/NodeUID fields are
// populated by kubelet and admitted only from the kubelet actually running
// that pod, via kube-apiserver's NodeRestriction admission plugin. TokenReview
// only proves the caller holds a valid, audience-scoped bound ServiceAccount
// token; it does not prove which specific pod instance presented it. Verifier
// narrows that gap with a live Pod lookup, and opportunistically with the
// token's own bound-object claims when the cluster's TokenReview response
// carries them (see boundObjectExtras) -- but the Pod lookup is the only
// piece guaranteed present, so it is required, and the extras are hardening,
// never a substitute for it.
package tokenbroker

import (
	"context"
	"fmt"
	"slices"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Well-known TokenReview status.user.extra keys carrying a bound token's
// pod/node binding, from the ServiceAccountTokenPodNodeInfo feature
// (k8s.io/apiserver/pkg/authentication/serviceaccount, not vendored in this
// module -- these are local literals, not an import, so verify them against
// a live TokenReview response (see the extras probe called for in this
// feature's design doc) before trusting them for anything beyond
// best-effort hardening. Verify() never requires them: whether a given
// cluster's token authenticator populates them at all is itself a
// Kubernetes feature that may not be enabled everywhere this broker runs.
const (
	podNameExtraKey  = "authentication.kubernetes.io/pod-name"
	podUIDExtraKey   = "authentication.kubernetes.io/pod-uid"
	nodeNameExtraKey = "authentication.kubernetes.io/node-name"
	nodeUIDExtraKey  = "authentication.kubernetes.io/node-uid"
)

const serviceAccountUsernamePrefix = "system:serviceaccount:"

// CallerIdentity is what Verifier establishes about an RPC caller.
type CallerIdentity struct {
	Namespace          string
	ServiceAccountName string
	ServiceAccountUID  string
	PodName            string
	PodUID             string
	// NodeName is the node the caller's pod is currently scheduled to,
	// per a live Pod lookup -- not kubelet-attested. Empty if the pod has
	// not yet been scheduled.
	NodeName string
}

// Verifier authenticates MintPodCertificate callers.
type Verifier struct {
	kc       kubernetes.Interface
	audience string
}

// NewVerifier returns a Verifier that requires tokens to be valid for the
// given audience. audience should be a value nothing else in the cluster
// requests, so a token minted for some other purpose can't be replayed here.
func NewVerifier(kc kubernetes.Interface, audience string) *Verifier {
	return &Verifier{kc: kc, audience: audience}
}

// Verify authenticates token via TokenReview and cross-checks
// claimedPodName/claimedPodUID -- the caller's own claim, sourced from the
// Downward API, never trusted on its own -- against a live Pod lookup: the
// pod must exist in the token's namespace, run as the token's
// ServiceAccount, and match the claimed UID. When the TokenReview response
// carries bound-object extras (see the package doc), they are additionally
// required to match; their absence is not itself an error.
func (v *Verifier) Verify(ctx context.Context, token, claimedPodName, claimedPodUID string) (*CallerIdentity, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	if claimedPodName == "" || claimedPodUID == "" {
		return nil, fmt.Errorf("pod_name and pod_uid are required")
	}

	review, err := v.kc.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{v.audience},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("while reviewing token: %w", err)
	}
	if !review.Status.Authenticated {
		return nil, fmt.Errorf("token review: not authenticated: %s", review.Status.Error)
	}
	// TokenReviewStatus.Audiences is the intersection of the requested
	// audiences and the token's own; per its doc comment, an EMPTY
	// intersection with Authenticated=true means the token carried no
	// audience restriction at all and was validated against the apiserver's
	// own default audience instead -- i.e. it was never actually scoped to
	// v.audience. Require the intersection to be non-empty and contain our
	// audience explicitly, so an audience-unbound (or differently-scoped)
	// token cannot authenticate here.
	if !slices.Contains(review.Status.Audiences, v.audience) {
		return nil, fmt.Errorf("token review: token is not valid for audience %q", v.audience)
	}

	namespace, serviceAccountName, ok := parseServiceAccountUsername(review.Status.User.Username)
	if !ok {
		return nil, fmt.Errorf("token review: username %q is not a service account", review.Status.User.Username)
	}

	pod, err := v.kc.CoreV1().Pods(namespace).Get(ctx, claimedPodName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, fmt.Errorf("pod %s/%s not found", namespace, claimedPodName)
		}
		return nil, fmt.Errorf("while getting pod %s/%s: %w", namespace, claimedPodName, err)
	}
	if string(pod.UID) != claimedPodUID {
		return nil, fmt.Errorf("claimed pod UID %q does not match pod %s/%s's actual UID %q", claimedPodUID, namespace, claimedPodName, pod.UID)
	}
	if pod.Spec.ServiceAccountName != serviceAccountName {
		return nil, fmt.Errorf("pod %s/%s does not run as service account %q", namespace, claimedPodName, serviceAccountName)
	}

	if err := checkBoundObjectExtras(review.Status.User.Extra, claimedPodName, claimedPodUID, pod.Spec.NodeName); err != nil {
		return nil, err
	}

	return &CallerIdentity{
		Namespace:          namespace,
		ServiceAccountName: serviceAccountName,
		ServiceAccountUID:  review.Status.User.UID,
		PodName:            claimedPodName,
		PodUID:             claimedPodUID,
		NodeName:           pod.Spec.NodeName,
	}, nil
}

// checkBoundObjectExtras requires the TokenReview extras to match the
// already-established identity when present, and is a no-op when they are
// absent. See the package doc for why absence is not itself an error.
func checkBoundObjectExtras(extra map[string]authenticationv1.ExtraValue, podName, podUID, nodeName string) error {
	if want, got := podName, firstExtraValue(extra, podNameExtraKey); got != "" && got != want {
		return fmt.Errorf("token's bound pod name %q does not match claimed pod name %q", got, want)
	}
	if want, got := podUID, firstExtraValue(extra, podUIDExtraKey); got != "" && got != want {
		return fmt.Errorf("token's bound pod UID %q does not match claimed pod UID %q", got, want)
	}
	if want, got := nodeName, firstExtraValue(extra, nodeNameExtraKey); got != "" && want != "" && got != want {
		return fmt.Errorf("token's bound node name %q does not match pod's node name %q", got, want)
	}
	return nil
}

func firstExtraValue(extra map[string]authenticationv1.ExtraValue, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// parseServiceAccountUsername splits a "system:serviceaccount:<ns>:<sa>"
// username into its namespace and service account name.
func parseServiceAccountUsername(username string) (namespace, name string, ok bool) {
	rest, ok := strings.CutPrefix(username, serviceAccountUsernamePrefix)
	if !ok {
		return "", "", false
	}
	namespace, name, ok = strings.Cut(rest, ":")
	if !ok || namespace == "" || name == "" {
		return "", "", false
	}
	return namespace, name, true
}
