# Running Agent Substrate on a fully-managed control plane (EKS/AKS)

This is a design note, not a shipped feature. It documents a real blocker
found by reading the code, and sketches a workaround scoped from that
reading. Nothing described in the "Proposed workaround" section is
implemented — it's a starting point for a fork, or for an upstream issue.

## Status: not supported out of the box, as of this writing

Agent Substrate's sandboxing, scheduling, and networking design is built on
plain Kubernetes primitives (Deployments, `NetworkPolicy`, CRDs, device
plugins) that work on any cluster where you have cluster-admin RBAC,
managed or not. But `cmd/podcertcontroller` — the component that bootstraps
Substrate's internal mTLS PKI — hard-depends on two **alpha** Kubernetes
APIs that require kube-apiserver and kube-controller-manager feature gates.
On EKS and AKS, those control-plane components are fully managed by the
cloud provider; neither exposes feature-gate configuration to customers.
As the code stands today, Substrate cannot boot on a stock EKS or AKS
cluster.

## The blocker: `PodCertificateRequest` + `ClusterTrustBundle`

Every internal service identity in Substrate — `atelet`'s serving cert,
`ate-api-server`'s serving cert, `atunnel`'s cert, `atenet-router`'s and
`atenet-egress`'s certs, the egress MITM trust bundle — is provisioned
through a `podCertificate` projected volume source and read back via a
`certificates.k8s.io/v1beta1 ClusterTrustBundle` object. This appears in
six Deployment manifests:

- `manifests/ate-install/atelet.yaml`
- `manifests/ate-install/ate-api-server.yaml`
- `manifests/ate-install/ate-controller.yaml`
- `manifests/ate-install/atenet-router.yaml`
- `manifests/ate-install/atenet-egress.yaml`
- `manifests/ate-install/atenet-egress-with-sdsmint.yaml`

For example, `manifests/ate-install/atelet.yaml:276-288`:

```yaml
- name: podidentity
  projected:
    sources:
    - podCertificate:
        signerName: podidentity.podcert.ate.dev/identity
        keyType: ECDSAP256
        credentialBundlePath: credential-bundle.pem
    - clusterTrustBundle:
        signerName: podidentity.podcert.ate.dev/identity
        labelSelector:
          matchLabels:
            podcert.ate.dev/canarying: live
        path: trust-bundle.pem
```

`podCertificate` and `ClusterTrustBundle`/`ClusterTrustBundleProjection`
require feature gates that are off by default. The repository's own dev
tooling says so directly — `hack/create-kind-cluster.sh:102-109`:

```
# cmd/podcertcontroller depends on ClusterTrustBundle & PodCertificateRequest.
# They are not enabled by default as of Kubernetes v1.36
featureGates:
  ClusterTrustBundle: true
  ClusterTrustBundleProjection: true
  PodCertificateRequest: true
runtimeConfig:
  "certificates.k8s.io/v1beta1": "true"
```

These are kube-apiserver, kube-controller-manager, and kubelet flags. On a
self-managed cluster you set them yourself; on EKS/AKS you cannot — the API
server doesn't even serve the `certificates.k8s.io/v1beta1` resource group
without `runtimeConfig` set, and that's a server-side flag no customer of
either managed offering can touch. **This is checked against whatever
Kubernetes version EKS/AKS currently run** — if either provider has since
promoted these features toward GA (enabled-by-default), this constraint may
have loosened since `hack/create-kind-cluster.sh`'s comment was written.

There is no existing insecure/plaintext escape hatch for this specific
path. `credbundle.Loader` simply fails to find its input file if the
projected volume never populates, and TLS setup fails at startup —
confirmed by grepping `cmd/atelet`, `cmd/podcertcontroller`,
`internal/atunnel`, and `cmd/atenet` for `insecure`/`plaintext`/
`skip-verify`/`dev-mode`: the only hits found are unrelated (atenet's
`--credential-provider-insecure` dev flag is for its dial to the egress
credential provider, not this bootstrap path).

## Secondary portability considerations

These are not blockers on their own, but matter for planning an EKS/AKS
deployment once the PKI issue above is resolved:

- **Storage backend**: `cmd/ateapi/main.go:378-400` and
  `cmd/atelet/main.go:226-228` only implement GCS and S3 object-storage
  backends (`ATE_STORAGE_BACKEND=s3` switches to S3). S3 is native on AWS.
  Azure has no native S3 API, so AKS would need an S3-compatible endpoint
  (self-hosted MinIO, or similar) until a native Azure Blob backend exists.
- **Worker pod capabilities**: `cmd/atecontroller/internal/controllers/workerpool_apply.go:305-312`
  adds `NET_ADMIN`, `SYS_ADMIN`, `SYS_CHROOT`, `SYS_PTRACE` to worker pods
  (gVisor's `runsc` runs inside the pod, not via a node-level containerd
  `RuntimeClass`, so no node bootstrapping is required — just a permissive
  enough Pod Security Admission policy in the target namespace, which any
  cluster-admin can set).
- **Micro-VM class**: needs `/dev/kvm`, exposed through
  `internal/deviceplugin` — a standard kubelet device plugin, not a
  control-plane feature. The real constraint is whether the underlying node
  instance type has nested virtualization enabled, an instance-type choice
  rather than a permissions one.
- **Install tooling**: `hack/install-ate.sh` and `tools/setup-gcp` are
  GKE/GCP-specific (Workload Identity annotations, GKE-endpoint assumptions
  for telemetry — see e.g. `hack/install-ate.sh:1067` and the "Use base
  manifest for GKE" comments at lines 347 and 1101). This is a convenience-
  script limitation; the underlying `manifests/ate-install/*.yaml` are
  plain Kubernetes YAML that could be applied manually to any cluster,
  modulo the PKI blocker above.
- **CNI**: no hard dependency found beyond standard `NetworkPolicy`
  enforcement, so AWS VPC CNI (with the Calico add-on for policy
  enforcement) or Azure CNI should both work.

## Proposed workaround: a GA-only PKI bootstrap

### What `PodCertificateRequest` actually buys

`podidentitysigner.MakeCert`
(`cmd/podcertcontroller/internal/podidentitysigner/podidentitysigner.go:151-159`)
builds the `PodIdentity` X.509 extension entirely from `PodCertificateRequest.Spec`
fields, with a comment explaining why:

```go
// Fields are sourced from the PCR spec (attested by kube-apiserver) rather
// than the Pod object, which lacks the ServiceAccount and Node UIDs.
```

`Spec.{PodName, PodUID, ServiceAccountName, ServiceAccountUID, NodeName,
NodeUID}` are populated by kubelet, and kube-apiserver's `NodeRestriction`
admission plugin ensures a given kubelet can only create/update a PCR for a
pod actually scheduled to it. `signercontroller.go:179-180` notes this
directly: *"PodCertificateRequests don't have an approval stage, and the
node restriction / isolation check is handled by kube-apiserver."* The
signer's own cross-check against a live `Pods().Get()`
(`podidentitysigner.go:97-104`) is a secondary sanity check — the actual
trust comes from the NodeRestriction-gated write.

A plain `certificates.k8s.io/v1 CertificateSigningRequest` does **not**
give you this. A CSR's `spec.request` is a self-crafted PKCS#10 blob;
kube-apiserver only authenticates *who created the object* (a
ServiceAccount identity), not which pod instance or node made the request.
A compromised pod whose ServiceAccount is RBAC-permitted to create CSRs for
the custom signer could claim any `PodName`/`NodeName` it likes inside the
CSR — there's nothing to check it against.

### The GA substitute: bound ServiceAccount tokens + TokenReview

**Bound ServiceAccount tokens** (GA since Kubernetes 1.21, delivered via a
standard `serviceAccountToken` projected volume — kubelet automatically
sets `BoundObjectRef` to the requesting pod) plus **`TokenReview`**
(`authentication.k8s.io/v1`, GA) recover most of PCR's guarantee: pod
name/UID binding in a bound token is cryptographically verifiable via
`TokenReview`, with no feature gate required.

**What's weaker**: node attestation. Node-bound token claims may not be
available depending on cluster configuration, so the fallback is
`podcertcontroller` looking up the caller's `Pod` object server-side and
trusting `.spec.nodeName` — API-server-reported, not kubelet-attested. This
is the same trust level SPIRE's Kubernetes workload attestor and
pre-PodCertificateRequest Istio operate at; it's a reasonable deployment
tradeoff, but it should be a deliberate decision, not an overlooked one,
particularly since `internal/authz/model.fga` defines an `actor.host_node`
relation gating `can_mint_ateom_actor_credential` — worth explicitly
confirming whether that check's threat model tolerates
API-server-reported node identity versus kubelet-attested identity before
relying on it in this deployment mode.

### Architecture

Turn `podcertcontroller` from a passive Kubernetes-object watcher into
*also* an active RPC service — the same shape `atelet`'s `AteomSupport`
service already uses for `MintActorCertificate` over a local unix socket
(see `docs/dev/deep-dive.md`'s node-supervisor section), just one layer up
and over the network instead of a local socket.

```
              ┌─────────────────────────────┐
              │        podcertcontroller     │
              │  (existing localca pools,    │
              │   now also a gRPC service)   │
              └───────────────┬──────────────┘
                               │ MintPodCertificate(token, csrPEM)
                               │ ← TokenReview(token) to authenticate
                               │
      ┌────────────────────────┼─────────────────────────┐
      │                        │                          │
┌─────┴──────┐          ┌──────┴──────┐           ┌───────┴──────┐
│ ate-api-    │          │   atelet    │           │ atenet-router│
│ server pod  │          │    pod      │           │  / -egress   │
│             │          │             │           │     pod      │
│ init-       │          │ init-       │           │ init-        │
│ container:  │          │ container:  │           │ container:   │
│  keygen+CSR │          │  keygen+CSR │           │  keygen+CSR  │
│  bound token│          │  bound token│           │  bound token │
│  → RPC call │          │  → RPC call │           │  → RPC call  │
│  → write    │          │  → write    │           │  → write     │
│  credential-│          │  credential-│           │  credential- │
│  bundle.pem │          │  bundle.pem │           │  bundle.pem  │
└─────────────┘          └─────────────┘           └──────────────┘
```

Each pod's init container (or a refresh-loop sidecar, since certs need
re-minting before expiry — the "magic" kubelet auto-rotation provides for
`podCertificate` volumes must be reimplemented client-side here):

1. Generates a local keypair (private key never leaves the pod).
2. Builds a PKCS#10 CSR.
3. Reads its own bound ServiceAccount token from a normal
   `serviceAccountToken` projected volume, requested with a custom
   audience (e.g. `podcertcontroller.ate.dev`) — GA, auto-rotated by
   kubelet, no feature gate.
4. Calls `podcertcontroller`'s new `MintPodCertificate(token, csrPEM)` RPC.
5. Writes the returned certificate chain + its own private key to the same
   `credential-bundle.pem` path the manifests already reference
   (`ate-api-server.yaml:211-214` etc.) — **`internal/credbundle` needs no
   changes**; it already just parses PEM at a path, agnostic to how the
   file got there.

`podcertcontroller`'s handler:

1. Calls `TokenReview` (GA) to authenticate the token, extracting
   `namespace`, `serviceaccount.name`, `serviceaccount.uid`, and (bound
   since 1.21) `pod.name`/`pod.uid` from the token's claims.
2. Checks the token's audience matches the expected value, as a defense
   against token reuse across services.
3. Looks up the caller's `Pod` object to resolve `nodeName` (see the
   node-attestation caveat above).
4. Calls the existing `internal/localca.Pool.CreateCertificate` and
   `internal/substratex509.AddPodIdentityToCertificate` — **unchanged**,
   they only operate on `x509.Certificate`/`crypto.PublicKey` values.
5. Returns the signed chain.

### Bootstrapping: how does the RPC call itself get secured?

This isn't circular. The trust-bundle distribution (below) uses `ConfigMap`
objects, which are readable from pod start via the normal in-cluster
kubeconfig — no TLS bootstrap dependency. A pod can mount the current trust
bundle at startup and use it to verify `podcertcontroller`'s own serving
certificate (which `podcertcontroller` signs from the same CA pool it
already manages, exactly as it does today) when dialing the RPC. There's no
new bootstrap problem introduced.

### Trust-bundle distribution: `ClusterTrustBundle` → `ConfigMap`

`cmd/atecontroller/internal/controllers/egressmitmtrust_controller.go`
already reads its input from a plain `Secret`
(`egress-mitm-ca-pool`, via `localca.Unmarshal(secret.Data["pool"])`) — it
only converts that into a `ClusterTrustBundle` object as *output*
(`buildEgressMITMTrustBundleApplyConfig`, `egressmitmtrust_controller.go:100-110`).
Swapping the output to a `ConfigMap` (same PEM string, under a `Data` key)
is mechanical: change the apply-config type, drop the
`certificates.k8s.io` RBAC, and change consumers' `clusterTrustBundle:`
projected-volume sources to `configMap:` sources. The `podidentitysigner`/
`servicednssigner` trust bundles follow the same pattern — their
`DesiredClusterTrustBundles()` methods become `DesiredConfigMaps()`, a
trivial retype.

### What stays untouched

Confirmed by direct reading, not inference:

- **`internal/localca`** — `Pool.CreateCertificate`/`Pool.TrustAnchors()`
  operate purely on `x509.Certificate`/`crypto.PublicKey`. No K8s API
  awareness at all.
- **`internal/substratex509`** — `AddPodIdentityToCertificate`/
  `PodIdentityFromCertificate` encode/decode a custom X.509 extension
  to/from `*x509.Certificate`. No K8s API awareness.
- **`internal/credbundle`** — `Loader`/`Parse` read and PEM-decode a file
  path. The package doc mentions "the Kubernetes Pod Certificates
  mechanism" descriptively, but the code has no dependency on it — any
  writer producing the same PEM layout at the same path works unchanged.
- **`ate-api-server`'s external-caller authentication**
  (`cmd/ateapi/internal/oidcjwt`) — generic OIDC-discovery + JWKS
  verification against bound ServiceAccount tokens, a GA mechanism since
  1.21. Both EKS (IRSA/Pod Identity) and AKS (Workload Identity) expose the
  equivalent public OIDC issuer for the same underlying feature. `kubectl-ate`
  and `atecontroller` authenticating to `ateapi` need zero changes on
  EKS/AKS today; this half of Substrate's security story was never blocked
  by the alpha APIs. Only the internal service-to-service mTLS bootstrap
  (`podcertcontroller`) is affected.

### RBAC requirements

`podcertcontroller` needs `create` on `authentication.k8s.io/v1
tokenreviews` — covered by the well-known `system:auth-delegator`
ClusterRole, standard practice, and ordinary RBAC any cluster-admin user
can grant on EKS/AKS without control-plane access.

### Scope estimate

| Component | Change |
|---|---|
| `internal/localca`, `internal/substratex509`, `internal/credbundle` | None |
| `cmd/ateapi/internal/oidcjwt`, external caller auth | None |
| `signercontroller.go` (259 lines) | Replaced: informer/workqueue → gRPC request handler |
| `podidentitysigner.go` / `servicednssigner.go` | `MakeCert` re-sourced from `TokenReview` result + CSR instead of `pcr.Spec` (~20–30 line diff each); `DesiredClusterTrustBundles` → `DesiredConfigMaps` (trivial retype) |
| `egressmitmtrust_controller.go` | Output type `ClusterTrustBundle` → `ConfigMap` (contained) |
| New init-container/sidecar binary | New, ~150–250 lines: keygen, CSR, bound-token read, RPC call, PEM write, refresh loop |
| Manifests (6 Deployments) | `podCertificate:`/`clusterTrustBundle:` volume sources → `configMap:` + init-container `emptyDir` |

Roughly 8–10 existing files plus one new small binary. A contained,
fork-scale patch — not a rewrite — because the actual crypto/PKI logic
(`localca`, `substratex509`, `credbundle`) needs no changes at all.

## Alternatives considered

- **Wait for GA.** `PodCertificateRequest` and `ClusterTrustBundle` are
  both tracked for graduation. If EKS/AKS's currently-supported Kubernetes
  version has since enabled either by default, re-check before building
  the workaround above — it may no longer be necessary.
- **Upstream contribution.** Given `AGENTS.md`'s own note that "the
  security story for Substrate is very early," a GA-API fallback signer
  mode is a plausible candidate for an upstream issue or PR rather than a
  private fork, since any cluster without these alpha APIs enabled hits
  the same wall.
- **Accept the weaker (API-server-reported, not kubelet-attested) node
  trust level explicitly**, and gate that decision behind a deployment-mode
  flag rather than silently downgrading it — keeps the security posture
  auditable rather than implicit.

## Open questions before implementing

1. Does anything beyond `can_mint_ateom_actor_credential` in
   `internal/authz/model.fga` rely on kubelet-attested node identity in a
   way that a TokenReview-derived, API-server-reported `nodeName` wouldn't
   satisfy? (Recall from `docs/dev/deep-dive.md` that authz isn't actually
   enforced anywhere yet — this may be moot today, but matters once it is
   wired in.)
2. What cert lifetime and refresh cadence should the init-container/sidecar
   use, given kubelet's own bound-token rotation cadence and the existing
   short-lived-cert assumptions baked into `internal/localca`'s rotation
   model?
3. Should the new `MintPodCertificate` RPC live inside
   `cmd/podcertcontroller` itself, or as a separate deployment, given
   `podcertcontroller`'s existing rendezvous-hashing work-sharding
   (`internal/rendezvous`) was designed around per-`PodCertificateRequest`-key
   ownership, not per-RPC-call load balancing?
