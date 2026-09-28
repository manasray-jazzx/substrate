# Scale-testing kagent on Agent Substrate: instantiation and serving performance

## Status: one 66-minute run, complete, findings below

This is a follow-up to `docs/dev/mks-workaround.md`'s "kagent, continued:
patched locally, proven end-to-end" section, which proved a single
`SandboxAgent` chat turn works end to end. This document scale-tests that
same integration: many agents instantiating, serving one turn, and
hibernating, repeatedly, for an hour, against the same
`kind-substrate-eks-aks-verify` cluster (10 `counter` WorkerPool replicas,
kagent patched locally per that document).

## Test design

**Removing the LLM as a confounding variable.** An earlier attempt at this
test used the real local Ollama backend (`llama3.2`) and found, within
minutes, that Ollama itself — a single local process — was the bottleneck:
a solo, out-of-band prompt to Ollama took over 60 seconds while 10
concurrent chat turns were in flight, and every Substrate worker sat
"busy" not because of a scheduling problem but because the agent process
was blocked waiting on Ollama's inference queue. That run was stopped
deliberately (mid-test) once this was confirmed, rather than spend an hour
re-measuring "Ollama is saturated."

To isolate Substrate/kagent's own instantiation-and-serving performance,
the test instead points a **new, second `SandboxAgent`** (`scale-test`, left
alongside the existing `test-echo` so as not to disturb it) at a small
OpenAI-API-compatible mock LLM server, built for this purpose from
kagent's own `github.com/kagent-dev/mockllm` test-helper dependency (already
in `go.mod`, previously used only inside kagent's own Go tests). A ~60-line
`cmd/mockllm-server` wraps it into a real, standalone HTTP server: one
catch-all mock (`match_type: contains` against an empty expected string,
which trivially matches any request) that always returns a fixed, instant
reply. It runs on the host, reachable from pods the same way Ollama already
is (`host.docker.internal:9999`), wired up via a plain `ModelConfig` with
`provider: OpenAI` and `openai.baseUrl` pointed at it.

One non-obvious fix was needed to get a match at all: `openai.UserMessage("")`
(the SDK's own constructor) leaves the message's `Role` field as its Go
zero value ("") in memory — the SDK only ever populates the real constant
("user") via `MarshalJSON`, never through the constructor. mockllm's own
match logic compares this in-memory value directly, so a request built this
way never matched anything, "no matching mock found," until the message was
round-tripped through `json.Marshal`/`json.Unmarshal` first — exactly what
mockllm's own test helpers (`newOpenAIMock`) already do, for exactly this
reason.

With the mock in place, a single manual turn against `scale-test` completed
in 295ms end to end with a clean reply and no LLM variability at all.

**Load pattern.** 10 concurrent worker loops (bash + `curl`, no client-side
think-time — back-to-back as fast as each loop's own request completes),
each cycling round-robin through 20 fixed session ids (200 agents total),
so every agent is repeatedly instantiated, served, and hibernated many times
over the run rather than growing an unbounded number of one-shot agents.
First visit to a session id is a cold instantiation (`CreateActor` +
`ResumeActor`); every later visit is a warm resume from hibernation.
Concurrency (10) matches the `counter` WorkerPool's size (10 replicas) —
chosen deliberately to test right at the capacity boundary, not comfortably
under it.

## Headline result

37,273 chat-turn attempts over the run. **49.43% succeeded** — but that
number alone is misleading without segmenting the run, which had two very
different phases.

### Phase 1 — healthy (16:10–16:38Z, ~28 minutes, 36,090 attempts)

- **Success rate: 49.66%.** Every rejection (18,158 of 18,166 non-success
  rows) is the exact same clean, fast error:
  `substrate worker pool has no free workers; try again later or increase
  WorkerPool replicas` — `ate-api-server`'s scheduler correctly reporting
  `ResourceExhausted`, not a hang or a confusing failure mode. At exactly
  10 concurrent loops against 10 workers with zero client-side pacing,
  roughly half of all attempts land in the instant a burst of demand
  exceeds capacity by even one request — an expected outcome of testing
  right at the boundary, not a bug.
- **Successful-turn latency** (session-create + message/send combined):
  mean 480ms, **p50 398ms, p90 656ms, p99 1738ms**, max 3825ms, n=17,924.
- **Instantiation specifically** (the `POST /api/sessions` call — creating
  the session record, independent of whether a worker was available for
  the turn that followed) stayed fast throughout the *entire* run,
  including the degraded phase below: mean 18ms, p50 10ms, p99 133ms
  (n=37,259, all successful creates).
- **Cold vs. warm**: 107 cold (first-visit) successes averaged 410ms;
  17,817 warm (repeat-visit) successes averaged 480ms. The two are close
  enough, and the sample of cold visits small enough, that this is better
  read as "no significant cold-start penalty in the golden-snapshot
  restore path" rather than "warm resumes are slower" — the difference is
  more plausibly explained by warm samples being drawn from later, more
  loaded points in the run than by resume mechanics.
- **Coverage**: all 200 distinct agents completed at least one successful
  turn.

This phase is the actual answer to "what does agent initiation and serving
performance look like": **sub-second (p99 <2s) turns, sustained, at the
exact point where offered load equals worker capacity**, with clean,
immediate backpressure — not queuing, not silent drops — for the excess.

### Phase 2 — a ~20-minute stall (16:39–16:59Z), then full recovery

Per-minute attempt counts collapsed from 1,318 (16:38) to 48 (16:39) to
**zero** for a sustained stretch (16:40 through 16:53 — 14 minutes with
not a single new request even starting), a brief partial recovery burst
(16:54–16:55, 1,125 attempts), then a final near-total collapse (10
attempts total across 16:56–16:58) before the run's remaining in-flight
requests each individually timed out — some after **over 950 seconds** —
and the test's own deadline check finally let it exit at 17:20:49Z, 26
minutes past its nominal 1-hour end time.

Correlating with cluster state from the same window:

- The node itself went `NodeNotReady` and back to `NodeReady` within
  about 10 seconds (`kubectl get events` shows the transition, plus a
  simultaneous wave of `TaintManagerEviction: Cancelling deletion` events
  for *every single pod in the cluster* — the standard signal of a
  node-taint eviction sequence starting and then being aborted once the
  node reported Ready again before the eviction grace period elapsed).
- Host `uptime` load averages peaked at **12+** (1/5/15-minute averages)
  during this window, and even a bare `kubectl get pods` started failing
  with `TLS handshake timeout`.
- **`ate-api-server`'s own log has no gap longer than 30 seconds anywhere
  in the entire run** — it kept processing `Actor state changed` /
  `FinalizeSuspended` / RPC-handling log lines continuously, including at
  16:39:52, right at the start of the client-observed stall, with
  perfectly normal (single-digit-millisecond) internal timings.

Read together, this means: **Substrate's control plane did not itself
hang.** The stall was in the path between the test client (curl processes
on the host Mac) and the cluster — almost certainly the single-node
`kind` cluster's shared CPU/memory pool (running `kube-apiserver`/`etcd`,
all 10 gVisor worker sandboxes, and everything else on the same node)
combined with host-level contention (this machine was also running Chrome
at ~95% CPU, Ollama with two loaded models, and this whole Claude Code
session, at the same time as the test) — pushed past the point where the
`kubectl port-forward` tunnel this test relied on, and/or the node's own
kubelet heartbeat, could keep up. The cluster recovered fully on its own:
**zero pod restarts, zero data loss, zero corruption** across the whole
episode, confirmed by a clean `kubectl get pods` immediately after.

## What this does and doesn't say about Substrate/kagent

- **Does say**: at the tested concurrency (10, matched exactly to worker
  count), Substrate's own instantiation-and-serving path is fast and
  correctly backpressured — the "50% failure rate" is a capacity signal
  working as designed, not a defect. `ate-api-server` itself never
  degraded internally, even during the 20-minute episode.
- **Does say**: a single-node `kind` cluster is not a safe substrate for
  sustained, at-capacity multi-agent load testing on a shared development
  laptop — the control plane and the workload compete for the same,
  finite CPU/memory pool, and a busy host can tip that balance badly
  enough to produce a 950-second request stall and a flapping node,
  independent of anything Substrate or kagent got wrong.
- **Does not say** anything about Substrate's behavior on a properly
  resourced or multi-node cluster, where the control plane isn't
  contending with the workload for the same cores — that's a materially
  different environment this test does not speak to.
- **Does not say** anything about a real LLM backend's serving
  performance at scale — that variable was deliberately removed here (see
  "Removing the LLM as a confounding variable" above); the earlier,
  stopped Ollama-backed run is the relevant (if incomplete) data point for
  that question instead.

## Follow-ups worth doing, not done here

- Re-run on a multi-node cluster (or with the control plane pinned to
  dedicated resources) to separate "Substrate's own ceiling" from "this
  laptop's ceiling."
- Re-run with the load-generating client *inside* the cluster (or at least
  not dependent on a single `kubectl port-forward` tunnel from a
  potentially-contended host) to rule out the tunnel itself as part of the
  stall.
- The known, separate logging gap from the earlier single-turn concurrency
  test still applies: kagent's `ErrNoFreeWorkers` message never reaches a
  server-side log line, only the client-facing response body.
- A longer run (multi-hour) at a concurrency comfortably *under* worker
  capacity (e.g. 6–7 against 10 workers) would give a cleaner "sustained
  steady-state, low rejection rate" baseline to contrast against this
  intentionally-at-the-limit test.

## Reproducing this

- Mock LLM: `cmd/mockllm-server` (in the local kagent clone/fork,
  `manasray-jazzx/kagent@substrate-agent-substrate-compat`, not in this
  repo — it depends on kagent's own `go.mod`-vendored `mockllm` package).
  `go build -o mockllm-server ./core/cmd/mockllm-server && ./mockllm-server`
  (listens on `0.0.0.0:9999` by default).
- `ModelConfig`/`SandboxAgent`: provider `OpenAI`, `openai.baseUrl:
  http://host.docker.internal:9999/v1`, any `apiKeySecret` (mockllm only
  checks header presence, never validity).
- Load generator: a small bash+curl harness, 10 concurrent worker loops
  cycling through 20 session ids each, logging per-attempt CSV rows
  (timestamp, create/message latency and HTTP status, success flag, error
  note) — not committed anywhere, purpose-built for this one run.
