# Running Agent Substrate on a fully-managed control plane (EKS/AKS)

## Status: implemented on this branch, validated against a live cluster

This started as a design note describing a real blocker and sketching a
workaround. It's now implemented: `cmd/podcertcontroller/internal/tokenbroker`,
`cmd/podcertsidecar`, `internal/identitycert`, and
`manifests/ate-install/eks-aks/` on this branch. The design held up well
against the real code — the shape described below is close to what shipped
— but a handful of details turned out different once built, and three
separate rounds of live testing against real clusters caught real bugs
static review missed: two from the first pass against `podcertcontroller`
alone (see "The sidecar" below), one from actually standing up the bundled
Postgres (see "seven manifests" below), and four more from deploying and
exercising the *entire* stack end to end — `atecontroller`, worker pods,
and `atelet`, not just the identity-minting path — for the first time (see
"Worker pods: a ninth, differently-shaped consumer" and "Three more bugs
from full-stack live testing" below). Every one is called out explicitly
rather than silently corrected, since the gap between "designed" and
"built" — and between "the minting path works" and "the whole stack comes
up" — is worth keeping visible.

## The blocker: `PodCertificateRequest` + `ClusterTrustBundle`

Every internal service identity in Substrate — `atelet`'s serving cert,
`ate-api-server`'s serving cert, `atunnel`'s cert, `atenet-router`'s and
`atenet-egress`'s certs, the egress MITM trust bundle — is provisioned
through a `podCertificate` projected volume source and read back via a
`certificates.k8s.io/v1beta1 ClusterTrustBundle` object. This appears in
seven manifests -- six Deployments plus the bundled `postgres`
StatefulSet, found only once this branch's own full-stack live testing
actually stood up Postgres rather than just `podcertcontroller`:

- `manifests/ate-install/atelet.yaml`
- `manifests/ate-install/ate-api-server.yaml`
- `manifests/ate-install/ate-controller.yaml`
- `manifests/ate-install/atenet-router.yaml`
- `manifests/ate-install/atenet-egress.yaml`
- `manifests/ate-install/atenet-egress-with-sdsmint.yaml`
- `manifests/ate-install/postgres/postgres.yaml`

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
require feature gates that are off by default on most clusters today. The
repository's own dev tooling says so directly —
`hack/create-kind-cluster.sh:102-109`:

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
either managed offering can touch.

**Confirmed live, and the actual failure mode turned out broader than "gate
off."** Validating this branch's fix (`hack/verify-eks-aks-pki.sh`) against
a disposable `kind` v1.37.0 cluster found that cluster serves
`certificates.k8s.io/v1` — **not** `v1beta1` — for both
`PodCertificateRequest` and `ClusterTrustBundle`, with no feature gate
needed at all: these APIs have apparently moved toward GA upstream since
`hack/create-kind-cluster.sh`'s comment was written. `podcertcontroller`'s
Go code (and the base manifests) are hardcoded to the `v1beta1` client,
which 404s against a `v1`-only server exactly like it would against a
server where the alpha gate is simply off. **This means the constraint
isn't only "will EKS/AKS turn the gate on" — it's "will Substrate's own
client code target whatever API version a given cluster actually serves,"
which is a real, present gap on any cluster ahead of wherever `v1beta1`
support gets dropped upstream, independent of what EKS/AKS do.** The
workaround below sidesteps both failure modes identically, since it uses
neither `PodCertificateRequest` nor `ClusterTrustBundle` at all.

There is no insecure/plaintext escape hatch for this specific path in the
base install. `credbundle.Loader` simply fails to find its input file if
the projected volume never populates, and TLS setup fails at startup.

## Secondary portability considerations

These are not blockers on their own, but matter for planning an EKS/AKS
deployment once the PKI issue above is resolved:

- **Storage backend**: `cmd/ateapi/main.go:378-400` and
  `cmd/atelet/main.go:226-228` only implement GCS and S3 object-storage
  backends (`ATE_STORAGE_BACKEND=s3` switches to S3). S3 is native on AWS.
  Azure has no native S3 API, so AKS would need an S3-compatible endpoint
  (self-hosted MinIO, or similar) until a native Azure Blob backend exists.
  Unlike `ate-api-server` (which only touches the backend for specific
  operations, so a bad default just fails those), `atelet` constructs its
  storage client eagerly at startup — see "Three more bugs from full-stack
  live testing" below for the crash this caused and how
  `manifests/ate-install/eks-aks/atelet.yaml` now leaves the choice to a
  per-deployment ConfigMap/Secret instead of a hardcoded default.
- **Worker pod capabilities**: `cmd/atecontroller/internal/controllers/workerpool_apply.go`
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
  for telemetry). This is a convenience-script limitation; the underlying
  `manifests/ate-install/*.yaml` are plain Kubernetes YAML applicable to any
  cluster. `manifests/ate-install/eks-aks/` follows the same convention —
  full standalone manifests, not a script — for exactly this reason.
- **CNI**: no hard dependency found beyond standard `NetworkPolicy`
  enforcement, so AWS VPC CNI (with the Calico add-on for policy
  enforcement) or Azure CNI should both work.

## The implementation: a GA-only PKI bootstrap

### What `PodCertificateRequest` actually buys

`podidentitysigner.MakeCert` builds the `PodIdentity` X.509 extension
entirely from `PodCertificateRequest.Spec` fields, with a comment
explaining why:

```go
// Fields are sourced from the PCR spec (attested by kube-apiserver) rather
// than the Pod object, which lacks the ServiceAccount and Node UIDs.
```

`Spec.{PodName, PodUID, ServiceAccountName, ServiceAccountUID, NodeName,
NodeUID}` are populated by kubelet, and kube-apiserver's `NodeRestriction`
admission plugin ensures a given kubelet can only create/update a PCR for a
pod actually scheduled to it. The signer's own cross-check against a live
`Pods().Get()` is a secondary sanity check — the actual trust comes from
the NodeRestriction-gated write.

A plain `certificates.k8s.io/v1 CertificateSigningRequest` does **not**
give you this. A CSR's `spec.request` is a self-crafted PKCS#10 blob;
kube-apiserver only authenticates *who created the object* (a
ServiceAccount identity), not which pod instance or node made the request.
A compromised pod whose ServiceAccount is RBAC-permitted to create CSRs for
the custom signer could claim any `PodName`/`NodeName` it likes inside the
CSR — there's nothing to check it against. This is why the implementation
below uses bound ServiceAccount tokens + `TokenReview` instead of a plain
CSR flow.

### The GA substitute: bound ServiceAccount tokens + TokenReview

**Bound ServiceAccount tokens** (GA since Kubernetes 1.21, delivered via a
standard `serviceAccountToken` projected volume) plus **`TokenReview`**
(`authentication.k8s.io/v1`, GA) recover most of PCR's guarantee: pod
name/UID binding in a bound token is cryptographically verifiable via
`TokenReview`, with no feature gate required.

**What's weaker**: node attestation. `internal/substratex509`'s
`validatePodIdentity` requires `NodeUID`, which a Pod object alone doesn't
carry, so `tokenbroker.Server.mintPodIdentity` does a live `Node` GET by
the name a Pod GET resolved — API-server-reported, not kubelet-attested.
This is the same trust level SPIRE's Kubernetes workload attestor and
pre-`PodCertificateRequest` Istio operate at. It's a deliberate, stated
tradeoff: the `tokenbroker` package doc says so explicitly, and
`cmd/podcertcontroller/internal/tokenbroker/verifier.go`'s `Verifier.Verify`
additionally checks the TokenReview response's bound-object extras
(`authentication.kubernetes.io/pod-name` etc.) when a cluster's token
authenticator happens to populate them, as hardening on top of — never a
substitute for — the Pod/Node lookups.

### Architecture (as built)

Not a single "mode" — three independently flag-gated pieces on
`podcertcontroller`, each defaulting to today's behavior:

1. **`--enable-pcr-signing`** (default `true`) gates the two
   `PodCertificateRequest`-watching goroutines
   (`signercontroller.Controller.Run`). This exists because of a bug found
   while building this: `Run` blocks on `cache.WaitForCacheSync` for the PCR
   informer before it ever starts publishing trust bundles, so on a cluster
   where the PCR API is unavailable, that informer never syncs and the
   trust-bundle logic silently never runs at all — not merely erroring,
   never starting. The `eks-aks` overlay sets this to `false`.
2. **`--trust-bundle-configmap-namespace`** (default empty, disabled) makes
   `signercontroller.Controller.RunTrustBundlePublisher` — pulled out of
   `Run`'s informer-gated sequence specifically so it doesn't depend on it —
   also mirror each signer's trust bundle into a `ConfigMap` in that
   namespace, independently of (and never blocked by) the
   `ClusterTrustBundle` write next to it. The `eks-aks` overlay sets this to
   `ate-system`.
3. **`--token-mint-listen-address`** (default empty, disabled) starts the
   `PodCertificateBroker` gRPC service (`cmd/podcertcontroller/internal/tokenbroker`)
   on a TCP listener. Its own serving certificate is minted directly from
   the already-loaded service-DNS CA pool — `podcertcontroller` holds that
   CA material outright, so there's no bootstrap dependency on anything
   else. The `eks-aks` overlay sets this and exposes it via a new
   `Service`.

Each of the six consumer manifests gets one `podcertsidecar` init container
per certificate purpose it needs (`podidentity`, `servicedns`, or both), run
as a native sidecar (`restartPolicy: Always`, matching the pattern
`atenet-egress-with-sdsmint.yaml`'s existing `sdsmint` container already
uses in this repo). Each sidecar:

1. Generates a fresh ECDSA P-256 key and an empty-template CSR
   (`x509.CreateCertificateRequest`), mirroring `internal/atunnel/credential.go`'s
   `MintAteomCertificate` — the only other CSR-building code in this repo.
2. Reads its own bound ServiceAccount token from a `serviceAccountToken`
   projected volume (audience `podcertcontroller.ate.dev`).
3. Calls `PodCertificateBroker.MintPodCertificate` over TLS, verified
   against the **service-DNS** trust bundle regardless of which purpose
   it's minting — the broker's own listener always presents a
   servicedns-purpose serving certificate (see architecture point 3 above),
   a detail that's easy to get backwards and did get gotten backwards once
   while writing the manifests (fixed before commit, not live-caught, but
   worth flagging as an easy mistake).
4. Validates the returned chain (public key match, lifetime, `ClientAuth`
   EKU) and writes it via `credbundle.Write` (the write-side counterpart
   added to `internal/credbundle`, which previously only had `Parse`) to
   the same path the consuming container already reads via
   `credbundle.Loader` — no changes needed in any of the six consumers
   themselves.
5. Sleeps until 30 minutes before the certificate's `NotAfter`
   (`internal/identitycert.RefreshHeadroom`), then re-mints, polling every
   60s (matching `internal/localca.RefreshingPool`'s own file-change
   cadence) so a shutdown signal is noticed promptly.

A `startupProbe` gates each consumer's regular containers until its sidecar
has written a real bundle. **This is the second bug live testing caught**:
`podcertsidecar` builds on `gcr.io/distroless/static-debian13`, which has no
shell, so the first version of every probe — `exec: ["test", "-s", <path>]`
— failed with `exec: "test": executable file not found in $PATH` and every
pod stuck at `Init:0/1` despite the sidecar successfully minting the
certificate. Fixed with a `--check-file=<path>` flag on `podcertsidecar`
itself (exit 0 if the file exists and is non-empty, exit 1 otherwise), so
the probe re-invokes the same static binary — `exec: ["/ko-app/podcertsidecar",
"--check-file=<path>"]` — instead of needing a shell.

### Worker pods: a ninth, differently-shaped consumer

Every worker pod `atecontroller` creates carries its own `atunnel` identity,
provisioned exactly like the six static consumers above — but
`cmd/atecontroller/internal/controllers/workerpool_apply.go` builds that pod
spec dynamically, in Go, at reconcile time, rather than reading it from a
YAML file. This surfaced only once this branch's own full-stack live testing
got as far as actually creating a `WorkerPool` and watching its pod, well
after the six-manifest and Postgres gaps above were already fixed — the
identity path can look fully solved from `hack/verify-eks-aks-pki.sh` and a
healthy control plane alone, and still leave every worker pod unable to
start.

The fix mirrors the static-manifest pattern (`applyAtunnelPKIVolumes`
builds the same emptyDir/ConfigMap/serviceAccountToken volumes and
`podcert-sidecar-podidentity` init container, gated on a new
`tokenBrokerSettings.Address` parameter, empty by default), wired through a
new `WorkerPoolReconciler.WorkerTokenBrokerAddress` field and
`--worker-token-broker-address` flag on `atecontroller`.

**The image reference caught a real bug specific to this consumer being
Go code, not YAML.** `ko resolve` only rewrites a `ko://` string when it is
a *whole scalar value* somewhere in a static YAML file it's pointed at —
confirmed empirically: `ko resolve` left a `ko://...` string untouched when
it appeared as a substring inside a larger `--flag=value` arg, and only
rewrote it once split into two separate YAML list elements
(`- --flag` / `- ko://...`), each its own whole string. A Go string constant
hardcoded in `workerpool_apply.go` and passed to `WithImage` is therefore
never touched by `ko` at all — it reaches Kubernetes as the literal text
`ko://github.com/...`, an invalid image reference
(`Init:InvalidImageName`), regardless of when or how the binary was built.
The fix threads the resolved image reference in from outside instead:
`tokenBrokerSettings.SidecarImage`, a new `WorkerPoolReconciler` field and
`--worker-token-broker-sidecar-image` flag, set in
`manifests/ate-install/eks-aks/ate-controller.yaml` as two separate arg-list
elements specifically so `ko resolve` — which processes that static
manifest before `atecontroller` ever runs — rewrites it before
`atecontroller`'s own (never-`ko`-processed) binary ever sees the value.

### `podcertcontroller`'s own RPC handler

`tokenbroker.Server.MintPodCertificate`:

1. Calls `Verifier.Verify` (TokenReview + Pod lookup + optional extras
   hardening, per "What's weaker" above).
2. Parses the caller's CSR with `x509.ParseCertificateRequest` and calls
   `csr.CheckSignature()` — a real signature check the existing
   `podcertificate.PublicKey` helper doesn't do, since it only ever handled
   kubelet's own synthetic stub CSRs, never an untrusted client-submitted
   one. Only `csr.PublicKey` is ever used; any Subject/SAN fields the
   caller populated are discarded, so a caller can never influence its own
   issued identity.
3. Routes on an explicit `SignerPurpose` enum in the request
   (`podidentity` vs `servicedns`) to `internal/identitycert`'s
   template-building helpers — the same helpers `podidentitysigner.go`/
   `servicednssigner.go`'s `MakeCert` call for the `PodCertificateRequest`
   path, extracted into that shared package specifically so both paths stay
   provably in sync rather than duplicating the SAN-building logic.
4. Signs via the existing `localca.Pool.CreateCertificate` — unchanged.

### Trust-bundle distribution: `ClusterTrustBundle` → `ConfigMap`, at both existing sites

Two independent places produce `ClusterTrustBundle` objects, and both got
the same treatment — a `ConfigMap` mirror applied alongside, never gated on
the `ClusterTrustBundle` write's success:

- **`signercontroller.ensureBundles`** — now splits into
  `ensureClusterTrustBundle` and `ensureTrustBundleConfigMap`, called
  independently for the `podidentity`/`servicedns` signers'
  `DesiredClusterTrustBundles()` output. The ConfigMap is named after the
  `ClusterTrustBundle` name with `/` and `:` replaced by `-` (e.g.
  `podidentity.podcert.ate.dev:identity:primary-bundle` →
  `podidentity.podcert.ate.dev-identity-primary-bundle`), keyed
  `trust-bundle.pem` — the same file name every existing consumer already
  mounts a trust bundle at, so a `configMap:` projected-volume source drops
  in with no path changes.
- **`egressmitmtrust_controller.go`** — same treatment for the separate
  egress-MITM trust bundle, with its own RBAC regenerated via
  `controller-gen` (`+kubebuilder:rbac` marker → `manifests/ate-install/generated/role.yaml`,
  never hand-edited).

Confirmed live: `hack/verify-eks-aks-pki.sh` shows `ensureClusterTrustBundle`
failing continuously and harmlessly (`"the server could not find the
requested resource"`, retried every ~5s+jitter, never blocking) while
`ensureTrustBundleConfigMap` succeeds every time on the same tick.

### What stays untouched

Confirmed by direct reading, not inference:

- **`internal/localca`** — `Pool.CreateCertificate`/`Pool.TrustAnchors()`
  operate purely on `x509.Certificate`/`crypto.PublicKey`. No K8s API
  awareness at all.
- **`internal/substratex509`** — `AddPodIdentityToCertificate`/
  `PodIdentityFromCertificate` encode/decode a custom X.509 extension
  to/from `*x509.Certificate`. No K8s API awareness.
- **`internal/credbundle`** — `Loader`/`Parse` (and the new `Write`) read
  and PEM-decode/encode a file path. No dependency on how the file got
  there.
- **`ate-api-server`'s external-caller authentication**
  (`cmd/ateapi/internal/oidcjwt`) — generic OIDC-discovery + JWKS
  verification against bound ServiceAccount tokens, a GA mechanism since
  1.21. Both EKS (IRSA/Pod Identity) and AKS (Workload Identity) expose the
  equivalent public OIDC issuer for the same underlying feature. `kubectl-ate`
  and `atecontroller` authenticating to `ateapi` need zero changes on
  EKS/AKS; this half of Substrate's security story was never blocked by the
  alpha APIs. Only the internal service-to-service mTLS bootstrap
  (`podcertcontroller`) is affected.
- The PKI bootstrap itself required zero Go code changes in any of the six
  static consumer binaries (`atelet`, `ate-api-server`, `ate-controller`,
  `atenet-router`, `atenet-egress`, `atenet-egress-with-sdsmint`'s
  containers) or in `ateom`/worker pods — only manifests, plus
  `workerpool_apply.go` for the ninth consumer above. `atelet` and
  `atecontroller` did each need one small, unrelated Go fix once full-stack
  live testing exercised them for the first time — see "Three more bugs
  from full-stack live testing" below.

### Three more bugs from full-stack live testing

Getting a worker pod healthy (previous section) still left `atecontroller`
and `atelet` themselves unreliable on a cluster that serves neither
`certificates.k8s.io/v1beta1` nor GCP application default credentials —
found only once the *entire* stack was deployed and exercised together,
not just `podcertcontroller` and the identity-minting path in isolation:

- **`atecontroller` crash-looped every ~10s.**
  `egressmitmtrust_controller.go`'s `SetupWithManager` unconditionally
  registers a `Watches(&certsv1beta1.ClusterTrustBundle{}, ...)`
  EventSource. When the kind isn't registered at all, controller-runtime's
  cache-sync for that source times out, `Start()` returns an error, and by
  design the *whole* manager — every controller in the binary, not just
  this one — shuts down; `main()` then exits 1 and kubelet restarts the
  container, over and over. The brief window between each restart and the
  next crash was long enough for a `WorkerPool` reconcile to occasionally
  slip through, which is why this stayed hidden through earlier, shorter
  testing. Fixed with a one-time discovery probe at startup
  (`clusterTrustBundleV1beta1Available`, via `k8sClient.Discovery()`) rather
  than a new flag: unlike an operator-set flag, a capability probe cannot
  disagree with what the cluster actually serves, and
  `certificates.k8s.io` API listing confirms `ClusterTrustBundle` and
  `PodCertificateRequest` are coupled (both present or both absent at a
  given version) on every cluster checked so far, so one probe covers both.
  `EgressMITMTrustReconciler.SkipClusterTrustBundle`, set from that probe,
  skips the `Watch` registration *and* the `ClusterTrustBundle` apply/delete
  calls in `Reconcile` — skipping only the `Watch` would have stopped the
  crash-loop but left every reconcile returning an error and requeuing with
  backoff forever, since `k8errors.IsNotFound` does not match a RESTMapper
  "no matches for kind" error. The `ConfigMap` mirror (see "Trust-bundle
  distribution" above) is unaffected either way — it was already
  independent of the `ClusterTrustBundle` write's success.
- **`atelet` never started its `AteomSupport` socket, so every worker pod on
  the node hung indefinitely retrying its capacity report.** `atelet`'s
  `main()` similarly maintains a `ClusterTrustBundle` informer — for
  `systeminfovolume.go`'s egress-mitm trust bundle feature, `EgressTrustBundleName`, unrelated to
  `atelet`'s own identity — and called
  `clusterTrustBundleInformerFactory.WaitForCacheSync(stopCh)`
  *synchronously*, before reaching the code that listens on
  `ateompath.AteomSupportSocket` further down the same function. On a
  cluster where that kind never syncs, this wait never returns, so
  `atelet` never reaches the listener at all — not a crash, just permanent
  startup stall, silent apart from repeating reflector errors. Fixed by
  moving that specific `WaitForCacheSync` into a background goroutine: the
  feature it gates is already best-effort (the lister just serves `NotFound`
  until, if ever, it syncs), so nothing downstream actually needed the
  synchronous wait.
- **`atelet` also crash-looped, from two unrelated eager GCP dependencies.**
  `--gcp-auth-for-image-pulls` (default `true`) calls
  `googlecontainerauth.NewEnvAuthenticator`, and the default
  `ATE_STORAGE_BACKEND` (`gcs`) calls `ategcs.NewGCSClient` with real
  authentication — both at startup, both assuming a GKE node's metadata
  server for GCP application default credentials, which a managed non-GCP
  cluster has no equivalent of. Neither is part of the PKI bootstrap this
  document otherwise covers, but both are eager enough to crash-loop
  `atelet` immediately, the same way the PKI gaps did, so they had to be
  fixed to get this far. `manifests/ate-install/eks-aks/atelet.yaml` sets
  `--gcp-auth-for-image-pulls=false` and no longer sets `ATE_STORAGE_BACKEND`
  directly; it comes instead from an optional, per-deployment
  `atelet-envvars` ConfigMap / `atelet-secret-envvars` Secret (the same
  "customize without editing this manifest" pattern
  `ate-api-server.yaml` already uses for its Postgres DSN), in whatever
  shape the target cluster's real backend needs —
  `manifests/ate-install/kind/atelet/kustomization.yaml` shows the env vars
  an `s3`-compatible backend (e.g. a self-hosted MinIO/rustfs, or AWS S3
  itself) needs.

### RBAC

A **separate** `ClusterRole`/`ClusterRoleBinding`
(`podcert-token-broker`, `manifests/ate-install/eks-aks/pod-certificate-controller.yaml`),
bound to the same `default` ServiceAccount `podcertcontroller` already
runs as, kept apart from the existing `podcert-ate-dev-signer` role so this
managed-cluster-only grant stays visibly scoped:

- `authentication.k8s.io/tokenreviews`, verb `create`.
- `core/nodes`, verb `get` (for `NodeUID` resolution).
- `core/configmaps`, full CRUD — granted cluster-wide rather than scoped to
  `ate-system`, since a cross-namespace `Role`/`RoleBinding` would depend on
  `ate-system` already existing by the time this applies; narrow this if
  your install guarantees that ordering.

### Verification

`hack/verify-eks-aks-pki.sh` is the durable, re-runnable form of the live
validation this branch was built against:

1. Creates a disposable `kind` cluster (never touches your current
   `kubectl` context).
2. Confirms that cluster doesn't serve `certificates.k8s.io/v1beta1` —
   reproducing the blocker, whatever the underlying cause on a given
   cluster turns out to be.
3. Builds and loads `podcertcontroller` and `podcertsidecar` via `ko`,
   deploys the `eks-aks` variant of `pod-certificate-controller.yaml`.
4. Confirms both trust-bundle `ConfigMap` mirrors get published despite
   `ClusterTrustBundle` failing continuously.
5. Deploys a throwaway pod that mints a `podidentity` certificate through
   the full path (sidecar → bound token → `TokenReview` → broker RPC →
   `localca` signing) and inspects the result: confirmed to carry the
   correct SPIFFE SAN (`spiffe://cluster.local/ns/ate-system/sa/default`)
   and a fully-populated `PodIdentity` X.509 extension with real
   Namespace/ServiceAccountUID/PodUID/NodeName/NodeUID values resolved live
   from the cluster.
6. Deletes its cluster on exit (`--keep` to leave it running for
   inspection).

This does **not** exercise the full `ate-system` stack (no Postgres, no
`atelet`/`ateapi`/`atenet` deployed) — those six consumers are unchanged by
this feature (see "What stays untouched"), so the highest-value,
highest-risk thing to verify live was the new mechanism itself, not
Substrate's pre-existing control plane.

## Remaining gaps

- **The `ServiceAccountTokenPodNodeInfo` extras probe was never run against
  a real cluster.** `Verifier.checkBoundObjectExtras` treats
  `status.user.extra`'s bound-object keys as optional hardening, exactly
  because whether a given cluster's token authenticator populates them at
  all wasn't verified empirically — only exercised via unit tests against
  `k8s.io/client-go/kubernetes/fake`, which reflects whatever the test
  constructs, not real apiserver behavior. Confirm this against an actual
  EKS/AKS cluster (or record that it's absent) before relying on it for
  anything beyond defense-in-depth.
- **Node-attestation trust tradeoff remains as designed**: API-server-reported
  `NodeName`/`NodeUID`, not kubelet-attested. `internal/authz/model.fga`'s
  `actor.host_node` question from the original design note is moot for now,
  since authz still isn't enforced on any request path (see
  `docs/dev/deep-dive.md`), but revisit this once it is.
- **Namespace-scoped RBAC for the ConfigMap grant** — see RBAC above — is a
  worthwhile tightening for anyone who can guarantee `ate-system` exists
  before `podcertcontroller`'s RBAC applies.
- **`atenet-egress.yaml`/`atenet-egress-with-sdsmint.yaml`'s eks-aks variants
  are not wired into a combined install path** the way `agentgateway-egress/`
  etc. compose with `base/` — apply one of them alongside
  `manifests/ate-install/eks-aks/`'s `kustomize build` output manually, the
  same manual choice the base install already requires for picking an
  egress variant.
