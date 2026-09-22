# Agent Substrate: Code-Level Deep Dive

`docs/architecture.md` explains the *design*: actors, workers, the suspend/resume
lifecycle, and why a specialized control plane sits next to Kubernetes. This
document goes one level deeper, into the actual packages and RPCs that
implement that design, as of the current `main`. Where the implementation
diverges from what `docs/architecture.md` describes as the target design —
because a piece is bootstrapped but not wired in yet, or a workaround exists
for an upstream bug — that's called out explicitly, since it's easy to read
the higher-level doc and assume more is "live" than actually is.

Each section names the concrete files it's grounded in so you can jump
straight to the source. Line numbers reflect the state of the tree at the
time of writing and will drift; treat them as "look near here," not as
permanent anchors.

## Table of contents

1. [Control plane (`ateapi`)](#control-plane-ateapi)
2. [Node supervisor (`atelet` + `ateom`)](#node-supervisor-atelet--ateom)
3. [Networking (`atenet` + `atunnel`)](#networking-atenet--atunnel)
4. [Kubernetes controllers and CRDs](#kubernetes-controllers-and-crds)
5. [Security and identity](#security-and-identity)
6. [Observability](#observability)
7. [Cross-cutting packages](#cross-cutting-packages)
8. [Current vs. aspirational: consolidated gap list](#current-vs-aspirational-consolidated-gap-list)

---

## Control plane (`ateapi`)

`cmd/ateapi/main.go` is the entry point for `ate-api-server`, the brain of
the system described in `docs/architecture.md`.

### Startup wiring

`main()` (`cmd/ateapi/main.go:94-311`), in order:

- Logging/tracing/metrics via `internal/serverboot` (`InitLogger`,
  `InitTracing`, `InitMetrics`, `InitLogging` — all OTLP-based),
  `main.go:104-142`.
- Loads JWT auth config (`internal/ateapiauth.LoadAuthenticationConfig`) and
  builds one `ateapiauth.JWTProvider` per configured OIDC issuer via
  `cmd/ateapi/internal/oidcjwt` (`buildJWTProviders`, `main.go:492-518`) —
  this is the real bearer-token verification path.
- Connects to Postgres with retry (`connectPostgresWithRetries`,
  `main.go:423-445`, 30 attempts / 2s apart) via
  `cmd/ateapi/internal/store/atepg.Connect`.
- **OpenFGA bootstrap** (`main.go:165-177`): opens a dedicated pgx pool and
  calls `authz.NewServer(shutdownCtx, authzPool)`, which runs OpenFGA's Goose
  migrations and ensures its default store + embedded model exist. See
  [Security and identity](#security-and-identity) for why this is
  bootstrap-only today, not enforcement.
- Builds Kubernetes clientsets: a standard `kubernetes.Clientset` plus the
  generated ate clientset (`pkg/client/clientset/versioned`) via in-cluster
  config (`newKubeClients`, `main.go:449-463`).
- Builds gRPC server TLS creds (`buildServerCreds`, `main.go:468-490`):
  server cert from a credential-bundle file (`internal/credbundle.Loader`),
  optional client-cert verification against a pod-identity CA pool
  (`tls.VerifyClientCertIfGiven`). Client certs are optional at the
  transport level because certless clients (e.g. `kubectl-ate`) authenticate
  via Bearer token in the `ateapiauth` interceptor instead.
- `workercache.New(persistence, 5*time.Minute)` (`main.go:189`) — an
  in-memory cache of Worker records seeded from the store and kept warm.
  The scheduler reads from this cache, not the database, for low-latency
  placement decisions.
- Starts informers for `WorkerPool`/`SandboxConfig`/`CSIDriverConfig`
  (from the ate clientset), an atelet-pod informer, and a `StorageClass`
  informer, and waits for cache sync before serving (`main.go:194-211`).
- Builds an `objectstore.Store` (GCS by default; S3 if
  `ATE_STORAGE_BACKEND=s3`) via `newObjectStore` (`main.go:377-400`) — a
  comment notes this backend selection mirrors how `atelet` picks the
  backend it streams snapshot bytes through, so both ends agree on where a
  snapshot lives.
- Loads two "actor identity" material pools:
  `localca.NewRefreshingPool` (CA for actor-identity certs) and
  `localjwtauthority.NewRefreshingPool` (signing keys for actor-identity
  JWTs) — these back the `MintActorJWT`/`MintActorCertificate` RPCs.
- Constructs `controlapi.NewRPCService(...)` (`main.go:243-257`) — the
  `Control` gRPC service implementation — and
  `controlapi.NewActorTemplateReconciler(...)` (`main.go:260-261`), a
  background loop driving stored `ActorTemplate`s through golden-snapshot
  creation (see [Workflow engine](#workflow-engine)).
- Registers the gRPC server with an interceptor chain (`main.go:283-291`):
  `ateapiauth.UnaryServerInterceptor` (auth) →
  `ateinterceptors.MaxDeadlineUnaryInterceptor(10m)` →
  `ateinterceptors.ServerUnaryInterceptor` (structured logging) →
  `ateinterceptors.RejectUnknownFieldsUnaryInterceptor` (strict proto
  decoding — rejects any request carrying a field this server build doesn't
  recognize, at any nesting depth); registers the `Control` and
  `WorkerService` services.
- Graceful shutdown (`drainOnShutdown`, `main.go:313-336`): on SIGTERM, mark
  not-ready, wait a `drainDelay` (13s) for load-balancer deregistration,
  then `GracefulStop` with a `drainTimeout` (15s) hard cutoff.

### gRPC surface (`pkg/proto/ateapipb/ateapi.proto`)

Two services:

**`Control`** (`ateapi.proto:25`) — the primary API:

- Actor lifecycle: `GetActor`, `CreateActor`, `UpdateActor`, `SuspendActor`,
  `PauseActor`, `ResumeActor`, `RevertActor`, `DeleteActor`, `ListActors`.
- Actor identity: `MintActorJWT`, `MintActorCertificate`.
- Actor egress policy CRUD: `GetActorEgressPolicy`, `CreateActorEgressPolicy`,
  `UpdateActorEgressPolicy`, `DeleteActorEgressPolicy`.
- Tags (immutable snapshot pins — see `docs/architecture.md`): `CreateTag`,
  `GetTag`, `ListTags`, `UpdateTag`, `DeleteTag`.
- Workers: `ListWorkers`, `GetWorker`, `CreateWorker`, `UpdateWorker`,
  `DeleteWorker`, `DrainWorker`, `ListWorkerActorAssignments`.
- Atespaces (the tenancy boundary): `CreateAtespace`, `GetAtespace`,
  `ListAtespaces`, `DeleteAtespace`.
- ActorTemplates: `CreateActorTemplate`, `GetActorTemplate`,
  `ListActorTemplates`, `DeleteActorTemplate` — notably no
  `UpdateActorTemplate`, confirming `docs/architecture.md`'s "immutable
  definition of an actor-version."

**`WorkerService`** (`ateapi.proto:2010`) — a separate service facing
atelet/ateom rather than end users: `SetWorkerCapacity`, implemented by
`cmd/ateapi/internal/workerservice/capacity.go`.

### State store (`cmd/ateapi/internal/store`, `atepg`)

> Updated after merging upstream `d0d85c39` (`Split atepg.go into one file
> per resource/table`, upstream PR #1777): `atepg.go` was 1622 lines
> holding every table's logic; it's now 360 lines of shared connect/schema
> plumbing, with each resource's logic split into its own file
> (`actor.go`, `actor_template.go`, `atespace.go`, `egress_policy.go`,
> `lease.go`, `tag.go`, `worker.go`, `worker_assignment.go`). Citations
> below point at the current locations.

- Backend: PostgreSQL via `pgx/v5`. Package doc
  (`store/atepg/atepg.go:15-19`): *"Each table holds native SQL columns for
  fields SQL must operate on (primary keys, versions, pagination,
  update/delete preconditions) plus the complete protobuf message,
  binary-encoded, in a BYTEA column."* — proto is the source of truth; SQL
  columns exist only where the database itself needs to reason about a
  field (indexing, locking, pagination).
- `store.Interface` (`store/store.go:68`) is the full storage contract;
  `atepg.Persistence` implements it. Test support lives in
  `store/dockerenv` (local Postgres via Docker) and
  `store/storetest`/`storecontract` (a shared contract-test suite runnable
  against any `store.Interface` implementation).
- **Optimistic concurrency**: `store.Precondition` (`store.go:274`, built
  via `PreconditionFrom`) — mutating calls (`UpdateActor`, `UpdateWorker`,
  `UpdateTag`) pass a precondition derived from the caller's observed
  resource metadata, and the store rejects stale writes.
- **Row locking**: reads inside a mutation take
  `SELECT proto FROM workers WHERE name = $1 FOR UPDATE`
  (`worker.go:84`, `worker_assignment.go:34`; the equivalent actor-side lock
  is in `actor.go:147`) — a standard row-level lock scoped to the
  transaction.
- **Atomic worker↔actor binding** — `BindActorToWorker`
  (`worker_assignment.go:72`): locks the worker row `FOR UPDATE`, then
  `INSERT INTO worker_assignments (actor_uid, worker_name, proto) VALUES (...) ON CONFLICT (actor_uid) DO NOTHING`.
  Code comment: *"Insert first and let the conflict say whether the Actor
  was already bound. Checking with a read instead would miss a claim that
  commits after it, and both claims would believe they were first."* If the
  insert actually happened (`RowsAffected() == 1`), an `admit(worker)`
  capacity check runs under the same row lock, and a refusal rolls the
  insert back. This is the atomicity guarantee behind "an actor is bound to
  at most one worker."
- **Distributed leases**: `AcquireLease`/`acquireLease`/
  `renewLeaseLoop`/`releaseLease` (`lease.go:33-196`) — a token+TTL lease
  row per key (`lease:actor:<atespace>/<name>`, `lease:tag:<atespace>/<name>`),
  with a background renewal goroutine and `cleanupExpiredLeases`. This is
  what serializes concurrent Resume/Suspend/etc. calls on the same actor
  (see [Workflow engine](#workflow-engine)) — an explicit lease table, not a
  Postgres advisory lock (an advisory lock is used for schema bootstrap,
  `atepg.go:161`, and separately by the outbox maintenance loop to keep
  partition create/drop single-flighted across replicas, `outbox.go:322`).
- **Change feed**: a time-partitioned `worker_outbox` table
  (`createWorkerOutboxPartitions`/`outbox.go:301`,
  `dropExpiredWorkerOutboxPartitions`/`outbox.go:356`) with an
  `outboxMaintenance` background loop (`outbox.go:154`) that creates/drops
  partitions and a dedicated `watchPool` (max 3 conns: poller + maintenance
  + headroom — sized at `atepg.go:44-56`) for polling it. This backs a
  `WatchWorkers` capability (`store.WorkerWatch`/`WorkerEvent`,
  `store.go:349-382`) that never contends with request-serving queries.

### Scheduler (`cmd/ateapi/internal/scheduling`)

- `scheduling.Scheduler` interface (`scheduling.go:56-68`): `Schedule`
  (pick a free worker), `Applies` (non-capacity eligibility), `HasRoom`
  (capacity check) — split so a worker already hosting the actor being
  evaluated isn't excluded by its own occupancy.
- `Constraints` (`scheduling.go:32-49`): `SandboxClass` (never relaxed —
  snapshots aren't portable across sandbox classes), `TemplateSelector`/
  `ActorSelector` (Kubernetes label selectors matched against worker
  labels), `RequiredNodes` (pins placement to nodes holding a locally-cached
  snapshot), `Limits` (the actor's resource ask).
- `Schedule` (`scheduling.go:103-129`) reads the **entire worker fleet from
  `workercache`** in memory (`WorkerSource.Workers()` — not a DB query),
  filters to `Applies` (sandbox-class match + `WORKER_STATE_ACTIVE` + label
  selectors + node restriction), further filters to `HasRoom`, and picks
  **uniformly at random** among capacity-eligible candidates. There is no
  bin-packing or load-aware scoring today.
- `HasRoom` (`scheduling.go:158-185`): checks `used.Actors >= capacity.Actors`
  first (a hard per-worker actor-count cap), then parses declared resource
  quantities via `internal/resources.Quantities` and does
  `free.Sub(allocated); free.Covers(want)`. A dimension the worker doesn't
  report is treated as unconstrained; a capacity/allocation value that
  fails to parse is treated as *no room* — fail-safe against overcommit on
  unreadable state.
- An `eligibleWorkers` OTel histogram is emitted per scheduling attempt
  (`recordEligibleWorkers`) — telemetry on fleet pressure, not itself used
  for placement.
- Placement races aren't resolved by the scheduler, which only proposes a
  candidate — they're resolved by the store's `INSERT ... ON CONFLICT DO
  NOTHING` above. Two racing resumes can be handed the same candidate
  worker; only one bind wins, and the workflow retries scheduling on that
  outcome (`assignWorkerAttempt`, `workflow_resume.go:468`).

### Workflow engine (`cmd/ateapi/internal/controlapi/workflow*.go`)

Not a generic state-machine framework — a hand-written "ensure step"
pattern, documented on `stepSpan` (`workflow.go:44-49`):

> *"Workflow steps follow the ensure pattern: each step derives whether its
> work is already done from persisted state alone (calling `markSkipped`
> when so), validates the state-machine edge it is about to take, and
> persists what it changed before returning — so a re-entered workflow
> fast-forwards to wherever the previous attempt stopped."*

- `ActorWorkflow` (`workflow.go:104-115`) bundles the store, `workercache`,
  a `scheduling.Scheduler`, the atelet dialer, Kubernetes listers
  (`SandboxConfig`, `StorageClass`), metrics instruments, and an
  `objectstore.Store`.
- Each entry point follows the same shape, illustrated by `ResumeActor`
  (`workflow_resume.go:68-136`):
  1. A cheap pre-check *without* acquiring a lease: if the actor is already
     `RUNNING`, return immediately. This matters because the network router
     calls `ResumeActor` on every routed request, so the no-op path must be
     hot and must not touch the lease table.
  2. `acquireActorLease` (`workflow.go:216-218`) — a Postgres-backed lease
     named `lease:actor:<atespace>/<name>`. Contention returns
     `codes.Aborted` ("another operation is in progress for this actor")
     rather than blocking — this is the error `atenet-router`'s request
     parking treats as always-retryable (see
     [Networking](#networking-atenet--atunnel)).
  3. Sequential ensure-steps, each wrapped in `stepSpan` for tracing and
     re-checked against persisted state: `loadActorForResume` →
     `ensureVolumesCreated` → `ensureWorkerAssigned` (scheduler +
     `BindActorToWorker`, with `workerHoldingStaleClaim` handling races) →
     `ensureVolumesAttached` → `ensureAteletRestored` (the actual
     `RestoreWorkload` RPC to atelet) → `finalizeRunning`.
  4. Every `Actor`/`Worker` transition goes through `UpdateActor`/
     `UpdateWorker` with a `store.Precondition`, so a step racing against
     another workflow instance for the same resource fails cleanly instead
     of silently overwriting.
- Idempotency, stated directly in a comment on `ResumeActor`
  (`workflow_resume.go:65-67`): *"Idempotent: a re-entered workflow
  fast-forwards past the steps a previous attempt completed, deriving
  progress from the persisted actor alone."* There is no separate durable
  workflow log — the `Actor`/`Worker` records themselves are the
  workflow's checkpoint. This is the crash-recovery story.
- `WorkerWorkflow` (`workflow.go:170-193`) is a smaller, distinct type for
  worker-side multi-step operations (e.g. delete-with-release), since
  releasing an actor bound to a worker happens in-process rather than via a
  separate bind/release RPC.
- Structured lifecycle logging (`logActorStateChanged`/`logActorDeleted`,
  `workflow.go:73-101`) is emitted via `internal/actorevent` and `slog`,
  always reading off the *committed* record the store returned, never the
  in-flight request — "a call that returns is the one that made the
  change."
- `ActorTemplateReconciler` (`template_reconciler.go`) is a separate
  background loop (5 workqueue workers, `templateResyncInterval` default
  20s) that drives every stored `ActorTemplate` through creating a **golden
  actor**: resume it, wait `goldenSnapshotWarmup` (20s default, or a
  readiness probe) before snapshotting — producing the golden snapshot that
  `docs/architecture.md` describes as the cold-boot source for first-time
  actor instantiation.

---

## Node supervisor (`atelet` + `ateom`)

### Protocol layering

Two distinct gRPC packages, each covering one hop of
`ate-api-server → atelet → ateom`:

1. **`internal/proto/ateletpb`** — the atelet-facing API, spoken between
   `ate-api-server` and `atelet`.
   - `service AteomHerder` (served by atelet, called by ate-api-server over
     cluster networking, mTLS with pod identity): `Run`, `Checkpoint`,
     `Restore`, `UploadPausedCheckpoint`, `Terminate`.
   - `service AteomSupport` (served by atelet, called by `ateom` over a
     **local unix socket**, `ateompath.AteomSupportSocket`):
     `MintActorCertificate` (issues atunnel's per-actor cert) and
     `SetWorkerCapacity` (ateom reports node capacity back to atelet).
   - Key types: `WorkloadSpec`/`Container`/`Volume` (a cut-down, Pod-like
     spec), `SandboxAssets` (content-addressed sandbox binaries + pause
     image, keyed by GOARCH), `SnapshotScope` (`FULL`, `DATA`,
     `DATA_ON_GOLDEN` — restore-only, combines a template's golden snapshot
     with an actor's own durable data), `CheckpointType` (`LOCAL` vs
     `EXTERNAL`).
2. **`internal/proto/ateompb`** — the ateom-facing API, spoken between
   `atelet` and `ateom` in-pod over the pod network.
   - `service Ateom`: `RunWorkload`, `CheckpointWorkload`,
     `RestoreWorkload`, `TerminateWorkload`, plus two read-only stats RPCs —
     `GetWorkloadStats` (errors if the actor isn't present) and
     `GetActiveWorkloadStats` (discovery, never errors). Both bypass
     ateom's single lifecycle mutex so they don't stall behind an in-flight
     boot/checkpoint/restore.
   - `RunWorkloadRequest.runtime_asset_paths` is how the micro-VM runtime
     receives its extra binaries (`cloud-hypervisor`, `virtiofsd`,
     `kata-kernel`, `kata-image`); gVisor uses only `runsc_path`. A
     standalone `kata-config` asset (a Cloud Hypervisor TOML file) existed
     earlier but was dropped (upstream PR #1704): the micro-VM sizing
     defaults it held (`kata.DefaultMemoryMiB`/`kata.DefaultVCPUs`, 2 GiB /
     1 vCPU per `docs/api-guide.md`) now live in `ateom-microvm` itself
     rather than in a fetched config file.
   - Per the proto doc comment, ateom is a two-state machine: **available**
     ↔ **executing**. `RunWorkload`/`RestoreWorkload` move it to executing;
     `CheckpointWorkload` resets it to available (wiping the sandbox).

### `atelet` (`cmd/atelet/main.go`, ~2000 lines)

- **Startup** (`main.go:112`): parses flags, builds mTLS gRPC server creds
  (`--grpc-server-cred-bundle`, `--client-ca-certs`), sets up a Kubernetes
  clientset + informers for `atev1alpha1` CRDs, wires OTel metrics/OTLP
  relay, image-pull auth (GCP ADC via `google-containerregistry`), and
  starts **two gRPC listeners**: a TCP one (`AteomHerder`, for
  `ate-api-server`) and a **unix socket** at `ateompath.AteomSupportSocket`
  (`AteomSupport`, for local `ateom` pods) — `main.go:357-386`.
- **`AteomHerder`** is implemented directly in `main.go` (type at
  `main.go:432`):
  - `Run` (`main.go:473`) — fetches/verifies content-addressed
    `SandboxAssets` (SHA256-checked downloads), prepares the OCI bundle
    (`prepareOCIBundles`, `main.go:1420`), builds a matching
    `ateompb.WorkloadSpec` (`buildAteomWorkloadSpec`, `main.go:1507`), and
    dials the target ateom pod (`AteomDialer.DialAteomPod`,
    `main.go:1497,1621`) to call `RunWorkload`.
  - `Checkpoint` (`main.go:591`) — calls `CheckpointWorkload`, then either
    `moveLocalCheckpoint` (pause path, `main.go:740`) or
    `uploadExternalCheckpoint` → `uploadSnapshot` (`main.go:783,797`),
    which streams files to GCS/S3 via `cmd/atelet/internal/ategcs`.
  - `Restore` (`main.go:960`, the largest method) — downloads the
    checkpoint (`downloadExternalCheckpoint`/`downloadCombinedCheckpoint`
    for `DATA_ON_GOLDEN`, `main.go:1377,1388`) then calls
    `RestoreWorkload`.
  - `UploadPausedCheckpoint` (`main.go:835`) — uploads a local-only pause
    checkpoint (no ateom involved; the sandbox is already gone) via
    `uploadLocalCheckpointDir` (`main.go:884`), optionally narrowing a
    `FULL` capture down to a `DATA` upload
    (`narrowFullCaptureToData`, `main.go:942`).
  - `Terminate` (`main.go:1271`).
  - Every RPC has a dedicated `validate*Request` function
    (`main.go:1651-1826`) rejecting malformed requests before touching
    ateom or storage.
- **Local disk state**: atelet owns per-actor local directories
  (checkpoint dir, restore dir, image-cache dir) —
  `resetActorDirs`/`removeActorDirs` (`main.go:1863,1957`) reset/clean
  them; `writeFileAtomic` (`main.go:1827`) does crash-safe local metadata
  writes, including a `sandboxAssetsRecord` that pins the sandbox version
  used at `Run` so a later `Checkpoint` records the *same* version into the
  snapshot manifest — this is the concrete mechanism behind version-pinned,
  reproducible restores.
- **Drain on shutdown**: `drainOnShutdown` (`main.go:405`) with
  `--drain-delay`/`--drain-timeout` flags for graceful SIGTERM handling of
  in-flight RPCs.

### `cmd/atelet/internal/ategcs` — the snapshot storage mover

The concrete implementation of "streams snapshots to/from GCS/S3":

- Both GCS and S3 backends (`gcs.go`, `s3.go`) behind a small
  `ObjectStorage` interface (`objects.go:38`).
- **Sparse-file aware transfer**: memory snapshots are large, mostly-hole
  sparse files. `sparseparts.go`/`sparsezstd.go` compute extents via
  `SEEK_DATA`/`SEEK_HOLE` (`sparseExtents`, `sparseparts.go:45`) so only
  populated ranges are compressed and uploaded, and sparse files are
  reconstructed on download (`copyZstdSparse`, `objects.go:422`).
- **Parallel zstd** (`parzstd.go`, `newParZstd`, `parzstd.go:64`) — a
  worker-pool encoder so large uploads aren't compression-bound on a single
  core; `gcscompose.go` uploads big objects as multiple parts and
  server-side composes them (`composeAll`, `gcscompose.go:154`).
- **Ranged parallel downloads**: `rangedget.go`'s `rangedReader`
  (`rangedget.go:63`) schedules concurrent range GETs and reassembles them
  into a sequential decompression stream, mirrored in
  `gcsranged.go`/`s3ranged.go`.
- This package is deliberately private to `atelet` and distinct from
  **`internal/objectstore`**, the control-plane-side package `ateapi` uses
  for prefix-level list/copy/delete of snapshot objects *by name*. Its doc
  comment states the architectural split precisely: *"The control plane
  never handles those bytes: it copies server-side and deletes by name, so
  a multi-gigabyte memory image never transits ate-api."*
  (`internal/objectstore/objectstore.go:15-22`). **Atelet moves snapshot
  bytes; ateapi only manipulates snapshot object names.**

### `ateom-gvisor` (`cmd/ateom-gvisor/main.go`, ~1361 lines)

- A `runsc` wrapper type (`runsc.go:38`) shells out to the `runsc` binary
  for every lifecycle op: `cmdCreate`, `cmdStart`, `cmdCheckpoint`,
  `cmdFsCheckpoint`, `cmdPause`/`cmdResume`, `cmdRestore`, `cmdDelete`,
  `cmdState`, `cmdList`, `cmdKill`, `cmdWait`.
- The `--allow-connected-on-save` flag `docs/architecture.md` mentions is
  passed at `runsc.go:132` inside `cmdStart`, as a permanent workaround for
  a `runsc` bug resuming networking after checkpoint.
- `RunWorkload` (`main.go:644`): downloads/verifies the correct `runsc`
  version, prepares the OCI bundle, creates+starts the pause container
  then each app container.
- `CheckpointWorkload` (`main.go:768`): checkpoints the pause container
  (`rcmd.cmdCheckpoint`), tars durable-dir volumes
  (`tarDurableVolumes`), reports back the exact files `runsc` wrote
  (`listSnapshotFiles`, `main.go:874`) so atelet ships precisely that set
  rather than a hardcoded list, then cleans up containers, returning ateom
  to "available."
- `RestoreWorkload` (`main.go:944`): untars durable volumes, recreates+
  restores the pause container (`rcmd.cmdRestore`), then restores each app
  container with its own log pipe.
- Lifecycle ops (Run/Checkpoint/Restore) are serialized per-ateom by a
  `cancelableMutex` (`main.go:354`), with a separate fast path for
  `GetWorkloadStats` outside that mutex.
- `atunnel` is instantiated inside this binary (`runAtunnel`,
  `main.go:277`) — confirming atunnel is hosted by ateom, per
  `docs/architecture.md`.
- Per-actor networking (`activateActorNetworking`, `main.go:1200`) and
  egress gateway setup (`prepareActorEgress`, `main.go:1103`) happen here,
  over a private netns/veth.

### `ateom-microvm` (`cmd/ateom-microvm/`, ~639-line main.go + focused files)

The most architecturally interesting part of the node subsystem, and
unusually well-commented in the source.

- **Rootfs overlay assembly is host-side, not guest-side**
  (`rootfsupper.go:1-40`): each container's rootfs is
  `overlay(lower = OCI image bundle, upper/work = per-actor host dir)`,
  merged by the *host* kernel and served to the guest over a single
  virtio-fs share (`internal/kata/overlay_linux.go`). Rootfs writes
  therefore cost host disk/page-cache, not guest RAM — matching
  `docs/architecture.md`'s claim about writes being "reclaimable host page
  cache." The doc comment records two earlier designs that were tried and
  retired: a guest tmpfs upper (capped rootfs writes at tmpfs size, pinned
  every byte in guest RAM) and a guest-mounted overlay on a virtio-fs upper
  (needed three kernel workarounds) — useful context for why it's built
  this way.
- **`FULL` snapshots ship the rootfs upper as a tar**
  (`rootfsUpperTarFile`), taken while the guest is paused. Since the
  virtio-fs share is write-through (no `--writeback`), a paused guest's
  completed writes are already durable on the host upper, so the tar is
  complete without extra flushing. A `DATA`-scope snapshot skips this
  entirely — the workload cold-starts on restore.
- **`DurableDir` volumes** (`durable.go:17-35`): a host directory per
  volume under `ateompath.DurableDirVolumeMountsDir(actorUID)`, exposed to
  the guest at `SharedDir(actorUID)/durable` over the same virtio-fs share,
  shipped as a tar of the whole per-actor directory on snapshot. Because
  every volume is just a subdirectory of one share, an actor can have
  multiple `DurableDir` volumes at zero extra device cost — the concrete
  mechanism behind micro-VM lifting the single-`DurableDir` limit that
  still applies to gVisor (which mounts each durable dir as its own gofer
  mount).
- **Memory snapshot/restore via `userfaultfd`** (`internal/ch/`):
  - `MemRestoreOnDemand` vs `MemRestoreEager` restore modes
    (`prefault.go:22-29`) — `OnDemand` registers a userfaultfd handler and
    faults pages in lazily as the guest touches them, so an idle restored
    guest holds only its working set, not the whole snapshot.
  - **`MergeSparseOverlay`** (`internal/ch/merge.go:31-42`): cloud-hypervisor
    has no native differential-snapshot support, so after an `OnDemand`
    restore, a subsequent CH snapshot (`deltaFile`) only contains pages the
    guest actually faulted in since restore. Substrate reconstructs a
    complete, independently re-restorable snapshot by overlaying
    `deltaFile`'s populated byte ranges (found via `SEEK_DATA`/`SEEK_HOLE`)
    onto the prior full snapshot (`baseFile`) — described in the code
    comment as "a Firecracker-style differential snapshot implemented on
    top of CH." This is what lets the suspend/resume chain keep
    `OnDemand`'s fast restore while still producing full, restorable
    snapshots at every step.
  - `prefault.go` tracks a **version-specific CH bug window**
    (`prefaultingSince = [3]int{53,0,0}`, `prefaultingUntil` left open):
    affected CH releases unconditionally background-prefault every
    registered page on an `OnDemand` restore and refuse `vm.snapshot` until
    that finishes, referencing upstream CH issues #8150, #8556, #8525 — a
    live constraint, not a historical footnote.
  - `restorefds.go`, `createvm.go`, `guestclock.go` round out the CH API
    driver (`internal/ch/ch.go`, `api.go`).
- `internal/kata` provides the shared-fs directory/mount layout both
  `rootfsupper.go` and `durable.go` build on. `internal/reaper` is the
  micro-VM analog of `internal/childreap` (used generically — see
  [Cross-cutting packages](#cross-cutting-packages)).

### `internal/imagecache` — node-local OCI layer cache

Not mentioned in `docs/architecture.md`, but architecturally significant:

- A content-addressed pool of *unpacked* OCI image layers, one copy per
  node, shared across all actors on that node — an actor's rootfs is
  composed as a single overlay mount referencing cached layers instead of
  re-extracting the image on every start/resume.
- Explicitly replaces a prior design — an in-memory LRU of flattened
  tarballs in atelet, re-untarred on every start — citing GitHub issues for
  the memory-blowup and cold-restart-latency problems that motivated the
  rewrite. The package README quantifies the win: the `oci_unpack`
  restore-timing metric drops from ~15–20s to single-digit milliseconds on
  warm nodes.
- Privilege split is deliberate: `atelet` runs as plain root with every
  Linux capability dropped ("atelet does no mounts" — see
  `manifests/ate-install/atelet.yaml`), while `ateom` worker pods hold the
  privilege to actually perform the overlay mount.
- Cache correctness for mutable tags: resolving a tag ref costs one `HEAD`
  request to get a digest (the only safe cache key for a mutable tag);
  digest refs hit the cache with zero network I/O.

### A restore scope not in the high-level docs

`SNAPSHOT_SCOPE_DATA_ON_GOLDEN` is restore-only and composes a template's
golden snapshot (memory + full filesystem delta) with an actor's own
durable-dir data at restore time — letting the first run of a *recurring*
actor skip re-running its full golden boot while still picking up whatever
durable state it accumulated previously.

The snapshot manifest is self-describing: both gVisor and micro-VM restores
read the pinned sandbox-binary/pause-image version out of the snapshot's
own recorded state, never trusting the caller (`RestoreRequest`'s proto
comment: "Sandbox binary config is not sent on restore: the snapshot is
self-describing"). This is what lets runtime upgrades avoid breaking
existing snapshots.

---

## Networking (`atenet` + `atunnel`)

### `atenet-router` ingress ext_proc handler

`cmd/atenet/main.go` is a 21-line shim; all logic lives under
`cmd/atenet/internal/router/**` (there's a `README.md` there worth reading
directly). `internal/atenet` itself is small (`headers.go`,
`ParseTargetActor`).

- `extproc.Server` implements Envoy's `extprocv3.ExternalProcessorServer.Process`
  (a bidi stream) and **only handles the `RequestHeaders` callback**
  (`extproc.go:100-115`) — routing decisions are made purely from headers,
  not body.
- `directionOf(req)` (`dispatch.go`) picks `ingress` vs `egress` from the
  Envoy **filter-chain name** the connection was accepted on
  (`extproc.go:133-155`) — never from anything in the request itself, so a
  client can't forge its way onto the authenticated egress trust path.
- One binary, `--mode` (`ingress`/`egress`/`all`) selects which handlers
  are registered; deployed in practice as two separate Deployments
  (`atenet-router` for ingress, `atenet-egress` for egress) that scale
  independently.
- Per-request latency/outcome is recorded via a bounded `QueryRecorder`
  (last 100 queries, for `/statusz`) and an OTel histogram (`routeDuration`,
  labeled by actor-template atespace/name and resume outcome — both
  bounded, low-cardinality values, per the cardinality rules discussed in
  [Observability](#observability)).

**Actor resolution and routing** (`ingress/ingress.go`),
`Handler.HandleRequestHeaders`:

1. Extracts trace context from the HTTP headers inside the
   `ProcessingRequest` (ext_proc gRPC metadata doesn't carry it) and starts
   a span linked to the gateway's ingress span.
2. Parses the target actor from the `ate-target-actor` header or an Envoy
   filter-state attribute into `atespace/name`.
3. Determines `targetPort`: defaults to 80; for CONNECT-based
   arbitrary-port ingress, reads the port from the
   `dev.ate.connect.authority` filter-state attribute instead.
4. Calls `h.resumer.ResumeActor(ctx, actorRef)` — blocks until the actor is
   `RUNNING` with a worker IP, or errors (see request parking below).
5. Builds Envoy `ORIGINAL_DST` dynamic metadata pointing at
   `<workerIP>:443` (atunnel's HTTPS ingress port) plus the resolved target
   port in a separate metadata field, and **overwrites** the
   `ate-target-actor` header (`OVERWRITE_IF_EXISTS_OR_ADD`) so a client
   can't retarget after resolution.

**Request parking / `ActorResumer`** (`ingress/resumer.go`,
`ingress/parking.go`, cross-checked against `docs/request-parking.md`):

- Problem: `ResumeActor` can return `ResourceExhausted` when the
  `WorkerPool` is momentarily saturated — expected under Substrate's
  oversubscription premise. This used to map straight to a client-visible
  503.
- **Singleflight per actor** (`flights map[string]*resumeActorFlight`):
  concurrent requests for the same actor share one in-flight `ResumeActor`
  call. The first caller is the "leader" (`runFlight`); later callers
  "join" (`awaitFlight`). Outcomes are tagged `Triggered`/`Joined`/`None`
  for metrics.
- **Budget is per-flight, not per-caller** (`resumer.go:213-219`): the
  shared retry loop's timeout context is created once, from the leader's
  trace context but a *detached* (non-cancelable) background context — so
  one caller disconnecting can't abort a resume the control plane has
  already committed work toward.
- **Retryable-error classification** (`retryable`, `resumer.go:170-179`):
  `Aborted` (concurrent-resume conflict — the same error the workflow
  engine's lease contention returns) is always retried;
  `ResourceExhausted`/`FailedPrecondition`/`Unavailable` (capacity, or
  transient ateapi unavailability such as a rolling restart) are retried
  only when parking is enabled. Everything else (`NotFound`,
  `DeadlineExceeded`, `PermissionDenied`, …) returns immediately.
- **Backoff**: exponential with no cap and effectively unlimited steps —
  deliberately, since `wait.Backoff`'s `Cap` would zero out `Steps` (ending
  retries) long before the parking budget elapses. The *budget context* is
  what actually bounds the loop, not the backoff's own step count.
- **Parking lot** (`parking.go`): a bounded, non-blocking admission gate
  (default max 1024 concurrent parked requests). A caller takes a slot only
  after its flight signals it's actually retrying (not on the fast path
  where resume succeeds immediately), and is shed with a 503 immediately if
  the lot is full rather than queuing unboundedly. Config
  (`ParkedRequestConfig`: `Budget` default 5s, `Max` default 1024, retry
  interval 100ms / factor 1.1 / jitter 0.1) is wired from CLI flags.
  `Max<=0` disables parking entirely (fail-fast mode, a separate 15s budget
  retrying only `Aborted`).
- **Budget vs. in-flight work**: per `docs/request-parking.md`, confirmed
  in code — when the budget elapses, the router stops issuing new resume
  attempts but does **not cancel** an attempt already in progress, since
  canceling could discard real, in-progress worker-restore work already
  committed on the control plane. A late success is served late; a late
  retryable failure surfaces as the same capacity 503. This is a
  deliberate design choice worth internalizing — budget is not a hard
  timeout.
- The parking-lot max and the ext_proc cluster's Envoy circuit breaker
  (`--extproc-max-requests`) are sized together: each parked request holds
  one ext_proc stream for its whole wait, so the breaker defaults to 2× the
  lot (1024/2048) to leave headroom for the fast path, validated at
  startup. Envoy's ext_proc message timeout is set to `budget + 5s`.

**Arbitrary-port ingress via CONNECT** (`xds.go`, router README): a client
reaches a non-default actor port by sending `CONNECT <actor-dns>:<port>` to
a dedicated listener (`--port-connect`/`--port-connect-tls`, defaults
8081/8444). Envoy terminates the CONNECT (`connect_terminate` chain), sets
the `dev.ate.connect.authority` filter-state key from the CONNECT's
authority, and **reinjects** the tunneled bytes into an internal listener
(`main_internal`) that runs through the *same* ingress ext_proc handler as
ordinary requests. Each HTTP request inside a long-lived CONNECT tunnel
therefore independently re-resumes/re-routes the actor if it has moved
workers since the tunnel opened — the tunnel is not a single sticky route.
Only HTTP(S) over the tunnel is supported today; raw TCP is not.

### `atunnel` — worker-side tunnel (`internal/atunnel`, hosted inside `ateom`)

`ingress.go` (502 lines), `egress.go` (305), `client.go` (239),
`credential.go` (168), `original_dst_linux.go` (114).

- `Server` is an activation-aware HTTPS reverse proxy — long-lived across
  many actor activations on the same worker, but only forwards traffic for
  the actor *currently* assigned (`active *activation`, guarded by a
  mutex).
- **Two listeners**: a regular HTTPS reverse-proxy listener (`Serve`, port
  443, what `atenet-router` dials for ordinary requests) and a separate
  **mTLS CONNECT listener** (`ServeConnect`) kept apart "so ordinary actor
  ingress remains a request proxy, while the router can use this listener
  for a bidirectional tunnel" (`ingress.go:256-260`).
- **mTLS**: `tls.RequireAndVerifyClientCert` plus a `VerifyConnection`
  callback checking the peer cert's URI SAN against a configured
  `AllowedClientID` (only atenet-router's identity may connect). The
  serving cert/key is reloaded per-connection via `GetCertificate` so
  kubelet's projected credential rotation takes effect without a pod
  restart — but the trust bundle (`ClientCAs`) is loaded once at startup,
  with a `TODO` noting it should reload per-connection too. A CA rotation
  today requires restarting long-lived worker pods before atunnel accepts
  new router certs — an asymmetry with the cert reload.
- **Protocol mirroring** (`protocolMirrorTransport`): detects true
  gRPC-over-HTTP/2 requests (HTTP/2, POST,
  `Content-Type: application/grpc[...]`) and forwards those as
  prior-knowledge h2c (needed for trailers/full-duplex streaming);
  everything else — even if it arrived over HTTP/2 — is downgraded to
  HTTP/1.1 on the actor leg, deliberately, to avoid breaking HTTP/1.1-only
  actors regardless of what the client negotiated at the edge.
- Target port selection: `pr.Rewrite` reads `X-Ate-Target-Port` (set by
  atenet-router from the CONNECT authority), strips it and
  `ate-target-actor` before forwarding, and rewrites the upstream URL's
  port accordingly — the mechanism that actually delivers arbitrary-port
  ingress to the right actor port.
- `Activate(atespace, actorName)`/`Deactivate(ctx)` flip which actor's
  traffic the proxy accepts; `Deactivate` also closes idle upstream
  connections.
- `authorize(r)` on every request checks against `s.active`; a mismatch
  (stale assignment — the router's control-plane data was stale and
  pointed at a worker that's since been reassigned) is rejected with
  `X-Ate-Assignment-Stale: true` rather than a generic error, letting the
  router distinguish "the actor app returned this status" from "you're
  talking to the wrong worker."
- Egress side (`egress.go`, `original_dst_linux.go`): reads the Linux
  `SO_ORIGINAL_DST` socket option, i.e. atunnel/ateom intercepts the
  actor's outbound connections transparently (via netns-scoped
  iptables/nftables redirect) to learn what the actor actually dialed
  before redirection to the egress path.

### Egress policy enforcement (`internal/egresspolicy` + `cmd/atenet/internal/router/egress`)

- Rules are evaluated in order over `Host` + dialed address; first match
  wins; an actor with no policy gets no tunnel at all.
- Three "legs" (Envoy filter chains) see different amounts of the request:
  the outer `egress` CONNECT leg only sees the actor cert plus dialed
  `IP:port`; `egress_cleartext` and `egress_tls_mitm` (SDS-terminated) legs
  see full HTTP semantics (`Host`, method, headers).
- Actor identity for policy decisions comes only from the CA-verified
  client certificate's `ActorIdentity` X.509 extension, checked against the
  ATE API — never from a client-controlled header.
- Policies are cached per-actor with a TTL (`--egress-policy-cache-ttl`,
  default 10s; 0 disables caching), bounding how stale a create/update/
  delete can be observed as.
- `inject_static_headers` (credential injection into egress requests) is
  now implemented (upstream PR #1335, landed after this doc's original
  research pass — see the note at the top of
  [Current vs. aspirational](#current-vs-aspirational-consolidated-gap-list)
  item 7). `applyEffects` (`cmd/atenet/internal/router/egress/credentials.go:62-77`)
  only injects on the TLS-terminated MITM leg (`egress_tls_mitm`) when a
  credential provider is configured; a cleartext request or no provider
  configured skips injection and lets the request through *without* the
  credential rather than denying it — but once injection is actually
  attempted, any failure to produce the credential fails closed. The
  gateway resolves `ate-secret://` URIs by calling a pluggable
  `credproviderpb` gRPC service, authenticating as the actor via its SPIFFE
  ID (`resources.ActorSPIFFEID`) — the provider trusts the gateway's
  assertion of which actor is asking. `cmd/credential-provider/kubernetes-secrets`
  is the reference implementation: a separate binary that is deliberately
  "the only component in the egress credential-injection path with
  Kubernetes access; the egress gateway and its injector never read
  Secrets directly" (package doc, `cmd/credential-provider/kubernetes-secrets/main.go:15-19`).
- MITM/TLS interception for HTTPS egress requires the "sdsmint" gateway
  variant (`docs/egress-trust-bundle.md`), which terminates the actor's TLS
  and re-originates it with a per-SNI leaf cert chaining to the gateway's
  own CA — actors must trust that CA (projected via a `systemInfo` volume)
  or their HTTPS calls break.

---

## Kubernetes controllers and CRDs

### `atecontroller` (`cmd/atecontroller/main.go`, ~208 lines)

A standard `controller-runtime` manager wired with three reconcilers plus
one non-controller-runtime sync loop:

1. **`WorkerPoolReconciler`**
   (`cmd/atecontroller/internal/controllers/workerpool_controller.go`) —
   watches `WorkerPool`, owns a `Deployment`. `Reconcile` (line 67) applies
   the Deployment via server-side apply
   (`applyDeployment`/`buildDeploymentApplyConfig`, field owner
   `workerpool-controller`, `client.ForceOwnership`,
   `workerpool_apply.go`, 561 lines — this is also where OTel env vars
   `OTEL_EXPORTER_OTLP_ENDPOINT`/`OTEL_METRIC_EXPORT_INTERVAL`/`_TIMEOUT`/
   `OTEL_TRACES_SAMPLER(_ARG)` get injected into ateom worker pods) then
   `syncStatus` copies `Deployment.Status.{Replicas,ReadyReplicas}` and the
   label selector into `WorkerPool.Status`. Registers two OTel
   `Int64ObservableUpDownCounter` instruments,
   `ate.workerpool.desired_workers` / `ate.workerpool.ready_workers`
   (`InitMetrics`, line 151). The Deployment's rollout strategy is set
   explicitly (`workerpool_apply.go:39-53`, added in upstream PR #1783):
   `maxSurge: 0` / `maxUnavailable: 10%` (Kubernetes raises a `0%`
   `maxUnavailable` to at least one pod regardless, so this makes a pool
   edit roll workers out gradually rather than stalling on a small pool),
   and `progressDeadlineSeconds: 4800` — deliberately above the 3600s
   worker termination grace period, so a batch waiting out an actor drain
   doesn't get misreported as a failed rollout by `kubectl rollout status`.
2. **`NetworkPolicyReconciler`** — for each `WorkerPool`, generates and
   server-side-applies (field owner `ate-networkpolicy`) a `NetworkPolicy`
   restricting worker-pod traffic to `atenet-router` in the `ate-system`
   namespace; garbage-collected via owner reference when the `WorkerPool`
   is deleted.
3. **`EgressMITMTrustReconciler`** — watches the `egress-mitm-ca-pool`
   Secret (scoped via a `cache.Options.ByObject` field selector, so the
   manager cache holds only that one Secret) and derives a
   `certificates.k8s.io/v1beta1` `ClusterTrustBundle` from the egress MITM
   CA pool (`internal/localca`) — the trust bundle egress-inspecting
   components read.
4. **`workersync.NewWorkerPoolSyncer`**
   (`cmd/atecontroller/internal/workersync/syncer.go`, 484 lines) — *not*
   a controller-runtime reconciler; runs its own informers (a `WorkerPool`
   informer from the generated clientset, plus a pod informer,
   `informer.go`, 51 lines) and "reconciles Kubernetes worker pods into the
   Worker registry behind the ateapi Control API." Watches pods labeled
   `ate.dev/worker-pool`, pushes lifecycle changes into `ateapi` over gRPC
   (`pkg/proto/ateapipb.ControlClient`) using 2 worker goroutines draining a
   workqueue, one key per pod (preserving per-pod ordering), plus a
   periodic full resync "to sweep for registry records that drifted without
   a pod event."

`main.go` startup order matters here for a subtle reason: OTel tracing/
metrics (`serverboot.InitTracing`/`InitMetricsPushOnly`, the latter
bridging controller-runtime's own Prometheus registry into the OTLP
pipeline via `prombridge.NewMetricProducer`) must initialize *before* the
`ateapi` gRPC client is built, because `otelgrpc.NewClientHandler()`
captures the global tracer/meter provider at construction time (an
explicit comment marks this). Dials `ateapi` via `ateapiauth.DialOptions`
(mTLS) at `--ateapi-conn-spec` (default
`k8s:///api.ate-system.svc:443`, resolved via `internal/k8sresolver`).

### CRDs (`pkg/api/v1alpha1`)

**`WorkerPool`** (namespaced, `workerpool_types.go`): `Spec.Replicas`
(required, ≥0), `Spec.WorkerImage` (required — the ateom image),
`Spec.SandboxClass` (`gvisor`|`microvm`, default `gvisor` — drives worker
pod shape such as KVM/vhost device mounts and node placement, though the
concrete binary is still selected by `WorkerImage`; the sandbox binaries
themselves come from the `SandboxConfig` each `ActorTemplate` names).
`Spec.Template` (optional): labels/annotations (max 64, CEL-validated to
reject the `ate.dev`/`*.ate.dev` reserved domain), node selector,
tolerations (max 16), priority class, node affinity, resource requirements.
`Status`: `Replicas`, `ReadyReplicas`, `Selector`. Has a `/scale`
subresource so HPA can target it directly.

**`SandboxConfig`** (cluster-scoped): `Spec.SandboxClass`
(`gvisor`|`microvm`, the same enum type shared with `WorkerPool`).
`Spec.PauseImage` must include a digest (CEL: `self.contains('@')`) — an
implementation detail of the sandbox pinned into the snapshot manifest so
restores reproduce the exact sandbox image. `Spec.Assets` is a
`map[GOARCH]map[assetName]AssetFile{URL, SHA256}` — content-addressed;
gVisor expects a `gvisor` asset (a `gvisor.tar.zstd` atelet extracts; a
legacy bare `runsc` binary asset is still accepted), micro-VM expects
`cloud-hypervisor`, `kata-kernel`, `kata-image`. Per-class requirement
enforcement is deferred to a `ValidatingAdmissionPolicy` rather than static
Go validation.

**`CSIDriverConfig`** (cluster-scoped): binds a CSI driver for durable
volumes. `DriverName` (regex-validated), `ControllerEndpoint` (must be
`tcp://` or `dns://` — a code comment flags a TODO to harden this
validation), `NodeSocketOverride` (optional, defaults to
`unix:///var/lib/kubelet/plugins/[DriverName]/csi.sock`),
`TLS.{Enabled, UsePodIdentity, ServerName}` — a CEL rule requires
`usePodIdentity=true` whenever `enabled=true`; manual certificates aren't
supported yet (another stated TODO for a `SecretReference` alternative).
`UsePodIdentity` reuses the same SPIFFE-style pod-identity certs described
in [Security and identity](#security-and-identity).

All three use `+genclient` to drive `pkg/client` codegen (pure
`client-gen`/`informer-gen`/`lister-gen` output), consumed directly by
`atecontroller` — not by `kubectl-ate`, since `ActorTemplate`/`Actor`/
`Worker`/tag records aren't Kubernetes objects at all; only `WorkerPool`/
`SandboxConfig`/`CSIDriverConfig` are.

### `podcertcontroller` (`cmd/podcertcontroller/main.go`, ~177 lines)

Implements two signers for the (beta) Kubernetes
`certificates.k8s.io/v1beta1` `PodCertificateRequest` API — not custom
CRDs. Per the package doc: `servicedns.ate.dev/identity` issues certs for
Kubernetes service DNS names; `podid.ate.dev/identity` issues certs
equivalent to KSA tokens. The doc comment notes both are "not unique to
Agent Substrate, and will eventually be replaced by signers... developed as
part of upstream Kubernetes."

- `internal/signercontroller.Controller` (261 lines) — a generic in-memory
  signing controller watching all `PodCertificateRequest` objects, queued
  by namespace/name, drained by `--workers-per-signer` goroutines,
  delegating to a `SignerImpl` interface (`SignerName`,
  `DesiredClusterTrustBundles`, `MakeCert`).
- `internal/servicednssigner` and `internal/podidentitysigner` implement
  `SignerImpl` for the two signer names, each backed by an
  `internal/localca.NewRefreshingPool` loaded from a CA-pool state file
  (`--service-dns-ca-pool`, `--pod-identity-ca-pool`) — a TODO notes this
  should reload on file change but currently loads once at startup, despite
  the "refreshing pool" name.
- Work is sharded across replicas via `internal/rendezvous`
  (rendezvous/HRW hashing keyed by pod namespace/name/UID/application
  name), so a given `PodCertificateRequest` key is owned by exactly one
  controller replica.

### `kubectl-ate` (`cmd/kubectl-ate/main.go` → `internal/cmd.Execute()`)

A Cobra-based `kubectl` plugin that is a **gRPC client of `ateapipb`**, not
a Kubernetes CRD client — confirming that `ActorTemplate`/`Actor`/`Worker`/
tag records are managed through the substrate API, not Kubernetes.
Persistent flags: `--kubeconfig`, `--context`, `--endpoint` (auto
port-forwards to `ateapi` through the Kubernetes API when omitted),
`--token-file` (bearer token, defaults to a Kubernetes ServiceAccount
token, or `-` for stdin), `--output {table,json,yaml}`, `--trace-enabled`.

Command surface (verb-then-noun, mirroring `kubectl`):

- Verbs: `get`, `create`, `update`, `delete`, `pause`, `resume`,
  `suspend`, `logs`, `top`.
- Nouns: `actor`/`actors`, `actor-template` (get/create `-f <manifest>`/
  delete — immutable, matching the proto's lack of `UpdateActorTemplate`),
  `atespace`/`atespaces`, `tag`/`tags`, `worker`/`workers` (get-only — no
  mutating verbs, since workers are managed by `atecontroller`/
  `WorkerPool`, not by users).
- `revert`/`revert_actor.go`: an `ate revert actor <name>` command, outside
  the standard verb/noun pattern.
- `admin.go`: `ate admin make-ca-pool` and `make-jwt-pool` — bootstrapping
  helpers for the `internal/localca`/`internal/localjwtauthority` state
  files consumed by `podcertcontroller`/`ateapi`.

### `ate-setup` (`cmd/ate-setup/main.go` → `internal/cmd.Execute()`)

Per its doc comment: "installs and tears down Agent Substrate on a
Kubernetes cluster. It is a Go port of `hack/install-ate.sh` and the
scripts it sources, which remain in place and still work; see
`cmd/ate-setup/commands.md` for the flag-by-flag mapping between the two."
This is an in-progress, currently dual-maintained reimplementation of the
shell-based cluster bootstrap as a Go CLI — both coexist and both work
today.

---

## Security and identity

### Identity model

Two distinct X.509-extension-based identities, plus a JWT identity:

- **Pod identity** (`internal/substratex509`): a `PodIdentity{Namespace,
  ServiceAccountName, ServiceAccountUID, PodName, PodUID, NodeName,
  NodeUID}` struct embedded as a custom X.509 extension (OID under
  `GoogleSubstratePEN = 1.3.6.1.4.1.11129.2.12`, subarc `.1`), JSON-encoded
  (unlike the upstream `kubernetesx509` it's modeled on, which uses ASN.1).
  Issued by `podcertcontroller`'s `podidentitysigner`.
- **Actor identity** (`substratex509`, subarc `.2`): an
  `ActorIdentity{Atespace, ActorName, ActorUid, Purpose}` extension,
  currently only valid for `Purpose = "atunnel"` — this is what
  `atenet-router`'s egress-policy checks verify against, and what
  `atunnel`'s own cert carries.
- **Actor identity JWT** (`internal/actoridjwt`): a separate JWT-based
  identity, RFC 7519 claims plus a `Substrate{Atespace, ActorName,
  ActorUID}` custom claim at `ate.dev`. This is the identity actors get
  minted via the `MintActorJWT` RPC (gated to a specific configured
  `actorIdentityJWTProvider` per `docs/authentication.md`), signed via
  `internal/localjwtauthority`.

### PKI plumbing

- **`internal/localca`**: a `Pool` abstraction over one-or-more CAs with an
  active-for-signing designation, enabling zero-downtime rotation (publish
  a new root inactive → age in → switch active → age out old → clean up,
  per the interface doc comment). `RefreshingPool` reloads pool state from
  a file every 60s so long-lived signers (identity broker, egress gateway)
  pick up admin-driven rotations without restart.
  `ConcretePool.CreateCertificate` does the actual `x509.CreateCertificate`
  signing; state round-trips through JSON with PKCS#8 keys. The doc
  explicitly notes a KMS/HSM-backed signer (no exportable key) can't be put
  in a pool file — a structural limitation of this design.
- **`internal/localjwtauthority`**: the same Pool/RefreshingPool/rotation
  pattern, for JWT signing rather than X.509. Supports RS256/RS384/RS512/
  ES256, hand-rolling JOSE signing rather than using a JWT library.
- **`internal/principal`**: a trivial context-carrier —
  `PrincipalInfo{ID, Kind, Issuer}` with `KindMTLS`/`KindJWT` constants,
  injected into `context.Context` by the auth interceptor and read back by
  `ateinterceptors` for structured logging.
- CA/JWT-authority consumers found across the tree: `atecontroller` (egress
  MITM trust controller), `ate-setup` (bootstraps the pools),
  `cmd/atenet/internal/sdsmint` (SDS cert minting for Envoy),
  `kubectl-ate` (admin commands to rotate pools), `podcertcontroller`,
  `ateapi`.

### Authentication (enforced)

`internal/ateapiauth/server.go` is the real gRPC-layer enforcement point —
`chainedServerAuthenticator`, installed as both the unary and stream server
interceptor:

1. First tries mTLS: extracts the client cert's first URI SAN (a SPIFFE ID)
   from `credentials.TLSInfo` (`mtlsPeerIdentity`).
2. Falls back to `Authorization: Bearer <JWT>`: peeks the unverified issuer
   (`unverifiedIssuer`), matches it against a configured
   `[]JWTProvider{Name, Issuer, Verify}`, and calls that provider's
   `Verify` callback.
3. Either path calls `principal.InjectContext`; **no credentials at all
   returns `codes.Unauthenticated`**, per the package doc.

This is genuinely wired in production: `cmd/ateapi/main.go` builds the auth
config (`~main.go:146`) including an `actorIdentityJWTIssuer` provider used
to gate `MintJWT`.

`internal/ateinterceptors` supplies the surrounding interceptor chain but
has no authz logic of its own:

- Logs every RPC (method, sanitized request/response, elapsed,
  `principal.FromContext`), sets an `x-server-elapsed-us` trailer,
  normalizes non-gRPC errors to `codes.Internal`.
- `sanitizeForLog`/`clearEnvFields` recursively strips any proto field
  literally named `env` before logging — a defense against leaking actor
  environment variables (secrets) into `ateapi`'s own logs.
- `MaxDeadlineUnaryInterceptor` caps request context lifetime.
- `RejectUnknownFieldsUnaryInterceptor` walks the proto message
  (`protorange.Range`) and refuses any request carrying an unrecognized
  wire field at any nesting depth — a strict-schema defense against
  clients sending fields this server build doesn't know about.

### Authorization — **bootstrapped, not enforced**

This is the single most important "current vs. aspirational" gap in the
whole codebase, and worth reading carefully.

`internal/authz/server.go` wraps an embedded **OpenFGA** server backed by
the same Postgres cluster:

- `NewServer` runs OpenFGA's own Goose migrations against the pool,
  serialized via a Postgres advisory lock
  (`pg_advisory_lock($1)`, fixed 64-bit ID `0x6174656667610000` — ASCII
  `atefga\0\0`), constructs the Postgres storage adapter, creates an
  in-process `server.Server`, and calls `ensureStoreAndModel`, which
  compiles the embedded `model.fga` DSL and either reuses a matching
  existing authorization model or writes a new one.
- `internal/authz/model.fga` defines a real, fairly complete
  relationship-based access model: `global` (singleton, `owner`/`viewer`),
  `atespace` (3-tier `owner`/`editor`/`viewer`, inheriting from `global`),
  `actor_template` and `actor` (policy stops at atespace scope), plus
  infrastructure-aware relations — `actor.host_node`, derived from
  `actor.scheduled_worker.host_node`, gating
  `can_mint_ateom_actor_credential` to only the node actually hosting the
  actor's worker (defense against a compromised node minting credentials
  for actors it doesn't host).

**But**: `authz.NewServer` is called exactly once, in `cmd/ateapi/main.go`,
and the returned server is only ever `defer`-closed. Its
`FGAServer()`/`StoreID()`/`ModelID()` accessors are never called anywhere
else in the tree, and there is no `openfgav1...Check(...)` call outside
`internal/authz` itself. **No request path performs an authorization
check.** This matches `docs/authentication.md` verbatim: *"Authorization
and RBAC are not implemented yet, so only configure providers whose users
should have full control of the entire control plane."* The commit that
added this bootstrap (`Initialize OpenFGA server on ATE API Server
bootstrap`) stood up the store/model/migration scaffolding; wiring a
`Check` call into the gRPC interceptor chain is the remaining work.

Anyone reading `model.fga` in isolation could reasonably assume it's
enforced today — it is not.

Separately, `cmd/ateapi/internal/ateletauth` handles the *ateapi→atelet*
direction (mTLS client identity when ateapi dials atelet), which is
distinct from the caller-facing authn/authz above.

---

## Observability

### `internal/otlprelay` — unix-socket OTLP forwarder

The most substantial piece of cross-cutting infra in the tree. `atelet`
runs this so worker pods (`ateom-gvisor`/`ateom-microvm`) don't need
network egress just to export telemetry. The package doc gives four
explicit motivations:

- **Blast-radius reduction**: a unix domain socket can't leave the node, so
  the untrusted actor pod's network egress can be fully denied.
- **Connection-count collapse**: many `ateom` instances → one
  `atelet`→collector gRPC connection.
- **No interference with `ateom`'s own egress-redirect iptables rules**: a
  unix socket isn't IP traffic.
- **No shutdown data loss**: `atelet` outlives the worker pod, so in-flight
  spans describing teardown survive.

Design specifics:

- Forwards OTLP `Export` requests verbatim (not decoded/re-exported) to
  preserve each `ateom`'s own resource attributes.
- `sourceGate` allowlists only
  `service.name ∈ {"ateom-gvisor", "ateom-microvm"}` — explicitly a
  protocol contract, not a security boundary (since `service.name` is
  client-supplied). Rejections are logged once per distinct name via a
  bounded (256-entry) LRU to stay diagnosable without spamming logs.
- `upstreamContext` deliberately **drops the incoming caller's gRPC
  metadata** and substitutes headers `atelet` resolves from its own
  `OTEL_EXPORTER_OTLP_HEADERS` env — the rationale: headers are
  credentials, unlike the resource payload, which is merely claimed
  identity.
- Dials upstream with `insecure.NewCredentials()` today (plaintext) — a
  known, tracked gap. The node-local unix-socket leg is trusted by
  construction; the `atelet`→collector leg that actually leaves the node is
  not yet secured, despite the architecture doc's "mTLS everywhere" claim
  for internal communication. This is a documented exception, not an
  oversight, but worth stating precisely.
- Socket mode `0600`, root-owned directory, explicit `os.Chmod` after
  `net.Listen` because the umask would otherwise leave it unreachable to a
  different-uid `ateom` process.

### Actor logs and events

- `internal/actorlog`: forwards an actor sandbox's stdout/stderr to the
  worker pod's stdout with `ate.*` identity labels attached, plus emits
  synthetic lifecycle events. Only lifecycle events carry OTel trace
  context, not per-log-line — one forwarder goroutine multiplexes the whole
  stream.
- `internal/actorevent`: a closed vocabulary of actor lifecycle events
  (`StateChanged`, `Crashed`), each an `Event{Name, Body, Severity, Keys}`
  value. A single `Log` call (renamed from `Emit` in upstream PR #1771, "Write
  both copies of an actor lifecycle event from one call") writes both the
  stdout record and its OTLP form from one call site, so the two can't drift
  — this replaced an earlier design where the caller passed the same
  `[]slog.Attr` to two separate call sites by hand. The package doc is
  explicit that this is not an slog-to-OTLP bridge (that would loop, since
  `serverboot` routes OTel SDK errors back through slog, and would put
  every component record on the wire rather than just the closed
  vocabulary), and that OTLP export happens off the actor-resume hot path
  via a batching processor, since exporting inline would put a blocking
  gRPC call on that path. The full `events` vocabulary
  (`actorevent.go:105`) is walked by a registry test cross-checking it
  against `docs/metrics/registry/events.yaml`, so an event added here and
  forgotten in the registry now fails a test rather than silently drifting.
- `internal/contextlogging`: an `slog.Handler` wrapper (`ContextHandler`)
  that pulls trace context out of `context.Context` and injects it as log
  attributes via `internal/ateattr`.

### The metric registry (`docs/metrics/registry/`, `docs/metrics/substrate.yaml`)

`docs/metrics/substrate.yaml` isn't read by any code — it's an explicit
human-and-agent reference — but its content is worth internalizing:

- **`cardinality_rules`**: `no-actor-identity` forbids `ate.actor.name`/
  `ate.actor.uid`/`ate.atespace`/`ate.actor.version`/
  `ate.actor.container.name` as metric labels (they belong on spans/logs
  instead — "too many values at the target of 1 billion actors");
  `bounded-or-catalog-scoped` requires every `ate.*` label to have a
  bounded value set; `error-type-not-parallel-counters` bans separate
  `*_errors_total` counters in favor of an `error.type`/
  `ate.failure.reason` attribute on the same instrument;
  `failure-keys-paired` and `pool-keys-paired` require certain attribute
  pairs to travel together. **None of these are mechanically enforced
  today** — each entry names how it could be (mostly
  `weaver registry live-check` against e2e telemetry).
- **`blind_spots`** — subsystems that emit no metrics, worth knowing before
  attributing a fault:
  - `cmd/ateapi/internal/store` (DB latency shows up as unexplained time in
    `ate.actor.lifecycle.operation.duration`, not as its own signal).
  - `cmd/ateapi/internal/workercache` (a stale fleet view can cause a
    resume assignment to a worker that isn't actually ready, with no
    signal in scheduler metrics).
  - Actor population (no gauge counts live actors by state today; tracked
    against a future `ate.actors` gauge).
  - `internal/imagecache` (hit/miss is counted; GC/eviction and image-prep
    time are not).
  - `cmd/podcertcontroller` (zero metrics).
  - `cmd/ateapi/internal/controlapi/template_reconciler.go` (golden
    snapshot build has no instruments).
  - `cmd/atenet/internal/router/drain.go` (shutdown/drain error outcome
    uncounted).
- **`bridged_metric_families`**: `atecontroller` re-exports the raw
  `controller-runtime` Prometheus registry
  (`controller_runtime_reconcile_*`, `workqueue_*`, `certwatcher_*`,
  `rest_client_*`, `leader_election_*`, `go_*`, `process_*`) into the OTLP
  pipeline rather than redefining them in the Weaver registry, specifically
  because a `controller-runtime` version bump would silently desync a
  hand-copied definition.

---

## Cross-cutting packages

- **`internal/sizing`** (`sizing.go`, 105 lines): right-sizes a sandbox
  from an actor's declared resource limits. `FromLimits(milliCPU,
  memoryBytes)` clamps negatives to 0 ("unset"). `VCPUs()` — used only by
  `ateom-microvm` — rounds millicores up to a whole vCPU count (min 1 if a
  limit is set, 0 if unset). `ApplyToOCISpec(*specs.Spec)` — used only by
  `ateom-gvisor` — writes `linux.resources.cpu.{period,quota}` (cgroup v2,
  100ms period) and `linux.resources.memory.limit` directly into the OCI
  spec so `runsc` applies them to the host cgroup leaf. The asymmetry is
  intentional: `ateom-microvm` doesn't call `ApplyToOCISpec` — it sizes the
  VM itself (VCPUs + guest memory), while the container cgroup limit for a
  micro-VM container comes from `atelet`-written pod resources instead.
- **`internal/readyz`**: polls a container's HTTP readiness endpoint from
  *inside* an `ateom` via a sub-millisecond poll loop, using an RST-vs-
  listen-socket timing trick to detect "server just started accepting
  connections" with minimal latency overhead — directly relevant to the
  <100ms activation-latency target in `docs/architecture.md`.
- **`internal/ateerrors`**: builds AIP-193-style `ErrorInfo`
  (`errdetails.ErrorInfo`) on top of gRPC `status`/`codes` — the
  structured-failure-reason plumbing the `failure-keys-paired` cardinality
  rule depends on.
- **`internal/version`**: build-time identity (`Version`, `Commit`,
  `BuildDate`) via `-ldflags -X`, falling back to
  `runtime/debug.ReadBuildInfo()` for a plain `go build`.
- **`internal/versionlabel`**: derives the `ate.dev/substrate-version`
  label consistently across nodes, the versioned `atelet` DaemonSet, and
  `WorkerPool` pod templates, so upgrade tooling can pin worker generations
  to a specific substrate build. Ships its own `internal/versionlabel/cmd`
  CLI wrapper so shell installers/upgraders don't reimplement the
  derivation.
- **`internal/k8sresolver`**: a custom gRPC `resolver.Builder` backed by
  Kubernetes `EndpointSlice` informers (not DNS) — how internal components
  dial each other pod-to-pod without kube-proxy/Service VIP overhead.
- **`internal/childreap`**: reaps orphaned children without racing
  subprocess waits, using `wait4(-1)` carefully so it doesn't steal an
  exit status `os/exec` is waiting on. Used generically across binaries;
  `ateom-microvm` has its own analog in `internal/reaper`.
- **`internal/resources`**: a shared model/validation layer for building
  Kubernetes objects (Deployments, NetworkPolicies) from `WorkerPool`/
  `Actor` state, plus SPIFFE ID construction and `Quantities` parsing
  (consumed by the scheduler's `HasRoom` check above).

---

## Current vs. aspirational: consolidated gap list

Pulling every "not yet implemented" and "TODO" surfaced above into one
place, since these are the details most likely to mislead a reader who
only skims `docs/architecture.md`:

1. **Authorization is bootstrapped, not enforced.** A complete OpenFGA
   model (`internal/authz/model.fga`) migrates cleanly into Postgres on
   every `ateapi` boot, but no RPC path calls `Check`. Authentication is
   real; authorization is not yet gating anything. See
   [Authorization](#authorization--bootstrapped-not-enforced).
2. **The OTLP relay's upstream leg is plaintext** (`insecure.NewCredentials()`
   in `internal/otlprelay`), a documented exception to "mTLS everywhere,"
   tracked against a specific issue.
3. **Scheduling is random-among-eligible**, not load- or cost-aware — a
   real current limitation of `cmd/ateapi/internal/scheduling`, not a
   design defect, but worth knowing before assuming any bin-packing
   behavior exists.
4. **`atunnel`'s client-CA trust bundle is loaded once at startup**; a CA
   rotation requires restarting long-lived worker pods, unlike the serving
   cert, which does reload per-connection.
5. **`podcertcontroller`'s CA/JWT-authority pool files are also loaded
   once at startup**, despite being named "refreshing pools" — hot-reload
   on file change is a stated TODO.
6. **`ateapi`'s own pod-identity CA pool for client-cert verification** is
   likewise loaded once, with an explicit TODO to periodically reload it.
7. ~~**Egress `inject_static_headers`** is schema-complete but
   unimplemented.~~ **Resolved** (upstream PR #1335): now implemented via a
   pluggable `credproviderpb` credential-provider service, with
   `cmd/credential-provider/kubernetes-secrets` as the reference K8s
   Secrets-backed implementation. See
   [Egress policy enforcement](#networking-atenet--atunnel).
8. **Arbitrary-port ingress is HTTP(S)-only**; raw TCP or other protocols
   on non-default ports aren't reachable via the CONNECT path today.
9. **`CSIDriverConfig.ControllerEndpoint` validation is explicitly flagged
   incomplete**, and manual (non-pod-identity) TLS certs for CSI drivers
   aren't supported yet.
10. **Metric cardinality rules in `docs/metrics/substrate.yaml` are all
    `enforced: false`** — conventions, not currently-guaranteed
    properties; several subsystems are named `blind_spots` with no metrics
    at all (control-plane store latency, worker-cache staleness, live
    actor population, image-cache GC, `podcertcontroller`, golden-snapshot
    build time, router drain outcomes).
11. **`ate-setup` and `hack/install-ate.sh` are a deliberate, currently
    dual-maintained migration in progress** — both work today.
12. **The gVisor sandbox class requires a `runsc` build with
    `--allow-connected-on-save`**, a permanent workaround for an upstream
    bug in resuming networking after checkpoint, not a temporary flag.
13. **The micro-VM class has a version-specific cloud-hypervisor bug
    window** (`prefaultingSince = 53.0.0`, `prefaultingUntil` still open)
    where affected CH releases unconditionally background-prefault every
    page on an `OnDemand` restore and refuse `vm.snapshot` until that
    finishes — a live constraint on which CH versions are safe to run.
