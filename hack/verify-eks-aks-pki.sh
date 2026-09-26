#!/usr/bin/env bash

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verifies the managed-cluster (EKS/AKS) PKI bootstrap path end-to-end: that
# podcertcontroller's TokenReview-authenticated PodCertificateBroker RPC and
# podcertsidecar actually mint a working certificate on a cluster where
# PodCertificateRequest/ClusterTrustBundle are unavailable, without ever
# deploying the full ate-system stack (no Postgres, no atelet/ateapi/atenet
# -- those consumers are unchanged by this feature; see
# manifests/ate-install/eks-aks/ and docs/dev/eks-aks-workaround.md).
#
# Creates a dedicated, disposable kind cluster -- never touches whatever
# cluster your current kubeconfig context points at -- deploys
# podcertcontroller's eks-aks variant, and mints a podidentity certificate
# for a throwaway pod via podcertsidecar. Fails loudly if any step doesn't
# produce what it should.
#
# Usage: hack/verify-eks-aks-pki.sh [--keep]
#   --keep  Leave the test cluster running afterwards (default: delete it).

set -o errexit -o nounset -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

CLUSTER_NAME="substrate-eks-aks-verify"
CONTEXT="kind-${CLUSTER_NAME}"
KEEP=false
TEST_POD_MANIFEST=""

if [[ "${1:-}" == "--keep" ]]; then
  KEEP=true
fi

cleanup() {
  [[ -n "${TEST_POD_MANIFEST}" ]] && rm -f "${TEST_POD_MANIFEST}"
  if [[ "${KEEP}" == "true" ]]; then
    echo "Leaving cluster '${CLUSTER_NAME}' running (--keep). Delete it with:"
    echo "  kind delete cluster --name ${CLUSTER_NAME}"
    return
  fi
  echo "Deleting cluster '${CLUSTER_NAME}'..."
  kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Creating disposable kind cluster '${CLUSTER_NAME}'..."
kind create cluster --name "${CLUSTER_NAME}" >/dev/null

echo "Confirming this cluster does not serve certificates.k8s.io/v1beta1 (the API"
echo "podcertcontroller's PodCertificateRequest-based signers depend on) -- this is"
echo "what actually reproduces the EKS/AKS blocker, whether the underlying cause on"
echo "a given cluster is an unset alpha feature gate or, as here, the API having"
echo "moved to a different version this codebase's v1beta1 client can't reach:"
if kubectl --context "${CONTEXT}" get --raw /apis/certificates.k8s.io/v1beta1 >/dev/null 2>&1; then
  echo "error: this kind cluster unexpectedly serves certificates.k8s.io/v1beta1;" >&2
  echo "       it does not reproduce the blocker this script verifies the fix for." >&2
  exit 1
fi
echo "  confirmed: certificates.k8s.io/v1beta1 is not served."

echo "Creating namespaces and CA pool secrets..."
kubectl --context "${CONTEXT}" create namespace podcertificate-controller-system >/dev/null
kubectl --context "${CONTEXT}" create namespace ate-system >/dev/null
go run ./cmd/kubectl-ate admin make-ca-pool \
  --ca-id=servicedns-1 --key-type=ECDSAP256 \
  --secret-namespace=podcertificate-controller-system --name=service-dns-ca-pool \
  --context="${CONTEXT}" >/dev/null
go run ./cmd/kubectl-ate admin make-ca-pool \
  --ca-id=podidentity-1 --key-type=ECDSAP256 \
  --secret-namespace=podcertificate-controller-system --name=pod-identity-ca-pool \
  --context="${CONTEXT}" >/dev/null

echo "Building and loading podcertcontroller and podcertsidecar images..."
export KIND_CLUSTER_NAME="${CLUSTER_NAME}"
export KO_DOCKER_REPO=kind.local
# Build for the local Docker platform only; a multi-arch build isn't needed
# for a throwaway local test cluster.
KO_PLATFORM="linux/$(docker version -f "{{.Server.Arch}}")"
./hack/run-tool.sh ko build --platform="${KO_PLATFORM}" ./cmd/podcertcontroller ./cmd/podcertsidecar >/dev/null

echo "Deploying podcertcontroller's eks-aks (managed-cluster) variant..."
./hack/run-tool.sh ko resolve --platform="${KO_PLATFORM}" -f manifests/ate-install/eks-aks/pod-certificate-controller.yaml \
  | kubectl --context "${CONTEXT}" apply -f - >/dev/null

echo "Waiting for podcertcontroller to become ready..."
kubectl --context "${CONTEXT}" -n podcertificate-controller-system \
  rollout status deployment/podcertificate-controller --timeout=120s

echo "Confirming the trust-bundle ConfigMap mirror was published despite"
echo "ClusterTrustBundle being unavailable (this is the bug fixed by pulling"
echo "trust-bundle publishing out of the PodCertificateRequest-informer-gated"
echo "loop -- see signercontroller.RunTrustBundlePublisher):"
# ensureBundles runs on its own ~5s (+jitter) ticker, independent of pod
# readiness, so give it a few ticks rather than checking exactly once.
for name in podidentity.podcert.ate.dev-identity-primary-bundle servicedns.podcert.ate.dev-identity-primary-bundle; do
  found=false
  for _ in $(seq 1 15); do
    if kubectl --context "${CONTEXT}" -n ate-system get configmap "${name}" >/dev/null 2>&1; then
      found=true
      break
    fi
    sleep 2
  done
  if [[ "${found}" != "true" ]]; then
    echo "error: ConfigMap ${name} was not published in ate-system within 30s" >&2
    exit 1
  fi
  echo "  confirmed: ConfigMap ${name} exists."
done

echo "Deploying a throwaway pod that mints a podidentity certificate via"
echo "podcertsidecar and podcertcontroller's PodCertificateBroker RPC..."
TEST_POD_MANIFEST="$(mktemp)"
cat >"${TEST_POD_MANIFEST}" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: podcert-sidecar-verify
  namespace: ate-system
spec:
  serviceAccountName: default
  initContainers:
  - name: podcert-sidecar-podidentity
    image: ko://github.com/agent-substrate/substrate/cmd/podcertsidecar
    restartPolicy: Always
    args:
    - --purpose=podidentity
    - --broker-address=podcertificate-controller.podcertificate-controller-system.svc:8443
    - --token-path=/var/run/secrets/podcert.ate.dev/token
    - --trust-bundle-path=/run/servicedns-ca/trust-bundle.pem
    - --credential-bundle-path=/run/podidentity/credential-bundle.pem
    - --pod-name=$(POD_NAME)
    - --pod-uid=$(POD_UID)
    env:
    - name: POD_NAME
      valueFrom: { fieldRef: { fieldPath: metadata.name } }
    - name: POD_UID
      valueFrom: { fieldRef: { fieldPath: metadata.uid } }
    volumeMounts:
    - name: podcert-token
      mountPath: /var/run/secrets/podcert.ate.dev
      readOnly: true
    - name: servicedns-ca
      mountPath: /run/servicedns-ca
      readOnly: true
    - name: podidentity
      mountPath: /run/podidentity
    startupProbe:
      exec:
        command: ["/ko-app/podcertsidecar", "--check-file=/run/podidentity/credential-bundle.pem"]
      periodSeconds: 1
      failureThreshold: 60
  containers:
  - name: main
    image: busybox
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: podidentity
      mountPath: /run/podidentity
      readOnly: true
  volumes:
  - name: podcert-token
    projected:
      sources:
      - serviceAccountToken:
          audience: podcertcontroller.ate.dev
          expirationSeconds: 3600
          path: token
  - name: servicedns-ca
    projected:
      sources:
      - configMap:
          name: servicedns.podcert.ate.dev-identity-primary-bundle
          items:
          - key: trust-bundle.pem
            path: trust-bundle.pem
  - name: podidentity
    emptyDir:
      medium: Memory
YAML
./hack/run-tool.sh ko resolve --platform="${KO_PLATFORM}" -f "${TEST_POD_MANIFEST}" \
  | kubectl --context "${CONTEXT}" apply -f - >/dev/null

echo "Waiting for the certificate to be minted (pod to become Ready)..."
kubectl --context "${CONTEXT}" -n ate-system wait pod/podcert-sidecar-verify \
  --for=condition=Ready --timeout=60s

echo "Verifying the minted certificate is a well-formed PodIdentity certificate..."
CERT_PEM="$(kubectl --context "${CONTEXT}" -n ate-system exec podcert-sidecar-verify -c main -- \
  sh -c 'awk "/BEGIN CERTIFICATE/,/END CERTIFICATE/" /run/podidentity/credential-bundle.pem')"
CERT_TEXT="$(openssl x509 -noout -text <<<"${CERT_PEM}")"
if ! grep -q "URI:spiffe://cluster.local/ns/ate-system/sa/default" <<<"${CERT_TEXT}"; then
  echo "error: minted certificate is missing the expected SPIFFE SAN" >&2
  echo "${CERT_TEXT}" >&2
  exit 1
fi
if ! grep -q "1.3.6.1.4.1.11129.2.12.1" <<<"${CERT_TEXT}"; then
  echo "error: minted certificate is missing the PodIdentity extension" >&2
  echo "${CERT_TEXT}" >&2
  exit 1
fi
echo "  confirmed: SPIFFE SAN and PodIdentity extension both present."

echo
echo "PASS: the managed-cluster PKI bootstrap path works end-to-end on a"
echo "cluster where podcertcontroller's PodCertificateRequest-based signers"
echo "cannot function."
