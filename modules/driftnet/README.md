# driftnet

Mobile runtime-instrumentation + compression-based novelty detection pipeline.

A rooted Android device (Frida + Shizuku) hooks a target app's network/crypto/fs
activity at runtime and streams metadata over a Tailscale mesh to a Go
aggregator, which scores every event with **Normalized Compression Distance
(NCD)** against a rolling per-app baseline. Events that don't compress well
against recent history — i.e. are structurally novel, not just statistically
rare — get triaged by a local Ollama model for a plain-English explanation.

No payload contents ever leave the device's local trust boundary in decrypted
form; hooks capture metadata (host, method, byte counts, cipher
algorithm/mode, file paths), not TLS-decrypted bodies.

## Why compression instead of a trained classifier

Kolmogorov complexity — the shortest program that produces a given string
— is uncomputable, but real compressors (zstd here) are a usable
approximation. This needs no training data, no labeled anomalies, and no
feature engineering — the compressor's own behavior *is* the signal.

**The exact mechanism isn't "concatenate and compress the whole thing"
— that was the original design, and it had two real bugs, both found by
testing it against actual traffic rather than trusting the formula on
paper (full account in `internal/novelty/ncd.go`'s package doc, worth
reading if you're touching this code — the failure modes are
instructive).** The current, working mechanism: compress the new event
*alone* using the recent baseline as a raw dictionary
(`C_dict(payload | baseline)`), and compare that against compressing the
same event with no dictionary at all (`C(payload)`). If the baseline lets
the compressor explain most of the event away, the ratio is low —
shares structure with normal traffic. If the baseline doesn't help at
all, the ratio approaches 1 — genuinely novel. This is dictionary-
assisted compression, not textbook Normalized Compression Distance
(NCD) — the field name `NCDScore` in the code (and `ncd_score` in the
JSON API, and the "NCD seismograph" label in the dashboard) is a holdover
from the original design and is technically a bit of a misnomer at this
point. Left as-is deliberately: renaming an established field name that
threads through the Go structs, the WAL's on-disk JSON format, the
JSON API, and the dashboard's JS is a much bigger, riskier change than
the terminological accuracy is worth — anyone touching the scoring code
itself has `ncd.go`'s package doc for the real story.

The LLM triage stage runs only *after* this scorer (or a rule) flags
something, to explain the flag in language, not to do the detection
itself.

## Architecture

```
┌───────────────────────┐    Tailscale WS/8787    ┌────────────────────────────┐
│  OnePlus 9R            │ ───────────────────────►│  Laptop (driftnetd)         │
│  (rooted, LineageOS)   │                          │                             │
│                        │                          │  ingest/  → per-kind score, │
│  frida-server          │                          │            rules eval,      │
│  ├─ agent/hooks.js     │                          │            attribution      │
│  │  (OkHttp+headers/   │                          │  novelty/ → 2 independent   │
│  │   crypto/fs/        │                          │            scorers: zstd    │
│  │   SharedPrefs/Log,  │                          │            (primary) +      │
│  │   secret scanning,  │                          │            DEFLATE          │
│  │   app version)      │                          │            (secondary),    │
│  └─ scripts/relay.py   │                          │            per device:      │
│     (Frida→WS bridge)  │                          │            app:kind         │
└───────────────────────┘                           │  rules/   → weak_cipher,    │
                                                     │            sensitive_path,  │
                                                     │            first_seen_host, │
                                                     │            app_updated,     │
                                                     │            secret_leak      │
                                                     │  attribution/ → which field │
                                                     │            drove the score  │
                                                     │  triage/  → Ollama 8B       │
                                                     │  api/     → dashboard JSON  │
                                                     │  store/   → data/events.wal │
                                                     │            (durable, WAL)   │
                                                     └────────────────────────────┘
```

Secret scanning happens entirely inside `agent/hooks.js`, on-device,
before anything crosses the WS connection — driftnetd never sees an
actual secret value, only a redacted pattern name (see "Secret/
credential leak detection" below).

## Setup

### 1. Tailscale mesh (do this first, everything else assumes it)

```bash
# on the laptop (Garuda)
sudo pacman -S tailscale
sudo systemctl enable --now tailscaled
tailscale up

# on the phone: install Tailscale from F-Droid or Play Store (works fine
# without GApps via F-Droid build), sign in with the same account
```

Get the laptop's tailnet address:
```bash
tailscale ip -4
# note this, e.g. 100.x.y.z — this is what driftnetd binds to
```

### 2. Laptop: build and run driftnetd

```bash
cd driftnet
go build -o bin/driftnetd ./cmd/driftnetd

# make sure Ollama is running with an 8B model pulled
ollama pull llama3.1:8b-instruct-q4_K_M   # fits your 6GB VRAM at Q4

# bind to your Tailscale IP, not 0.0.0.0 — the tailnet is the trust boundary
./bin/driftnetd -addr 100.x.y.z:8787 -data ./data \
  -ollama http://127.0.0.1:11434 \
  -model llama3.1:8b-instruct-q4_K_M
```

Verify: `curl http://100.x.y.z:8787/healthz` should return `ok`.

### 3. Phone: frida-server (rooted, via Magisk)

```bash
# match the frida-server version to your frida/frida-tools pip version —
# check with: frida --version (run on laptop after step 4)
adb shell "su -c 'wget -O /data/local/tmp/frida-server https://github.com/frida/frida/releases/download/17.15.3/frida-server-17.15.3-android-arm64.xz'"
adb shell "su -c 'xz -d /data/local/tmp/frida-server.xz'"
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

**Verify it's actually running before anything else** — this is the
single fastest way to know if the whole toolchain is talking to the
phone at all, before wondering whether a later failure is frida-server,
the target app, or something else entirely:
```bash
frida-ps -U
```
Should print a process list from the phone. If this hangs or errors,
nothing downstream will work either — check `adb devices` shows the
phone, and that frida-server actually started (`adb shell "su -c 'ps -A | grep frida'"`).

Shizuku can also start frida-server without a persistent root shell if you
prefer — wire it through `rish` (Shizuku's shell) instead of `su -c` above.

**On root/tamper detection: you already have a better tool than the one
built into this project.** `agent/hooks.js`'s `ENABLE_ANTI_DETECTION_BYPASS`
flag does two narrow, JS-level checks (`Debug.isDebuggerConnected`, a
handful of known root-indicator file paths) — useful as a fallback, but
Zygisk-based root hiding (Shamiko and similar modules, which hook at the
Zygote injection level rather than patching individual Java method calls
from inside the target process) is fundamentally more robust and hides
root from far more detection techniques at once. If Zygisk is already
active, try that route first; only reach for the JS-level flag if an app
still detects something Zygisk-level hiding didn't cover.

### 4. Laptop: Python relay dependencies

```bash
pip install frida==17.15.3 frida-tools websocket-client --break-system-packages
```//frida pip version MUST match frida-server version on the phone exactly.

### 5. Sanity-check the whole toolchain on something simple first

Before pointing any of this at Upjaoo, confirm hooks actually fire at all
against a trivial, known-simple target — isolates "is my setup broken"
from "does Upjaoo's app do something unusual," which are very different
problems to debug:
```bash
python3 scripts/relay.py --package com.android.settings \
  --driftnet-url ws://100.x.y.z:8787/ws/ingest
```
Open the Settings app on the phone, click around a bit (open Wi-Fi
settings, toggle something). You should see `network`/`fs` events
landing in the dashboard within a couple seconds. If nothing shows up
here, don't move on to Upjaoo yet — the problem is in the toolchain, not
in anything app-specific, and it'll be much easier to debug against a
simple system app than a real target.

### 6. Run it against the real target

```bash
# USB (adb) — simplest, use while wiring things up:
python3 scripts/relay.py --package com.example.targetapp \
  --driftnet-url ws://100.x.y.z:8787/ws/ingest

# fully wireless over Tailscale once frida-server is confirmed working:
#   adb over Tailscale needs adb tcpip mode + phone's tailnet IP, or just
#   use Frida's own network transport:
python3 scripts/relay.py --package com.example.targetapp \
  --host 100.a.b.c:27042 \
  --driftnet-url ws://100.x.y.z:8787/ws/ingest
```

Edit `agent/hooks.js`'s `DRIFTNET_WS_URL` / `DEVICE_ID` constants, or leave
them — the relay script controls the actual destination; the constants in
the JS are there for reference/if you invoke the script differently.

### 7. Watch it

Open `http://100.x.y.z:8787/` in a browser — that's the actual dashboard
(served by driftnetd itself, no separate frontend server needed): live
per-source NCD seismograph, event log with rule-match badges, flagged
drawer with triage text. From the iPhone, this works over Tailscale's
Magic DNS or the raw tailnet IP, no VPN config needed beyond having
Tailscale running.

Or hit the API directly:
```bash
curl -s http://100.x.y.z:8787/api/events/recent | jq
curl -s http://100.x.y.z:8787/api/events/flagged | jq
tail -f data/events.wal   # raw, not human readable, but proves durability
```

### 8. Optional: keep driftnetd running persistently

```ini
# ~/.config/systemd/user/driftnetd.service
[Unit]
Description=driftnet ingestion + novelty scoring service

[Service]
ExecStart=%h/driftnet/bin/driftnetd -addr 100.x.y.z:8787 -data %h/driftnet/data -web %h/driftnet/web -ollama http://127.0.0.1:11434 -model llama3.1:8b-instruct-q4_K_M
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now driftnetd
journalctl --user -u driftnetd -f   # tail logs
```

Swap in your actual Tailscale IP for `100.x.y.z` and adjust paths — this
is a template, not tested against your real filesystem layout, since I
don't have access to your actual machine from here.

## Rules engine: complementary to novelty, not a replacement

`internal/rules` closes a real gap: compression-based novelty answers
"does this look unlike anything this app has done before" — it has no
concept of "bad," only "different." A weak cipher used from an app's
first launch would score low novelty forever, because it IS the
baseline. Five rules run independently of novelty scoring:

- `weak_cipher` — DES, RC4, ECB mode, MD5, or SHA1 in a `crypto` event's
  algorithm field, plus legacy RSA PKCS1v1.5 padding. Scoped to
  `kind=="crypto"` only, to avoid incidental substring matches elsewhere.
  Catches both weak *encryption* (`Cipher.getInstance`) and weak
  *hashing* used elsewhere (`MessageDigest.getInstance`, e.g. MD5/SHA1
  for password storage) — both hooks emit the same
  `algorithm`/`transformation` field shape, so adding the
  `MessageDigest` hook required zero changes to this rule. One necessary
  exception: `RSA/ECB/<padding>` doesn't match the ECB-mode pattern,
  since "ECB" there is Java's naming placeholder for RSA's padding
  scheme, not a genuine block-cipher mode — see "Secret/credential leak
  detection" below for how this false positive was found.
- `sensitive_path` — filesystem paths matching credential/personal-data
  patterns (`contacts`, `wallet`, `.pem`, `keystore`, `shared_prefs`,
  etc.), scoped to `kind=="fs"`.
- `first_seen_host` — a network event's destination host that this
  source has never contacted before. Stateful, tracked per source key so
  it can't leak between apps. Warmup-gated (`Config.WarmupEvents`,
  default 40) so a freshly instrumented app's normal startup burst of
  first-time hosts doesn't flood the flagged view — see "Cold-start fix"
  below.
- `app_updated` — the app's version changed mid-session. Not a security
  finding by itself (see "App-update diffing" below) — shown as a
  distinct blue "info" badge in the dashboard, not the red badge the
  other four get, precisely so it doesn't read as alarming.
- `secret_leak` — a redacted match indicator (pattern name only, never
  the actual value) stamped by `agent/hooks.js`'s on-device secret
  scanner. Cross-cutting rather than kind-scoped: can appear on
  `network` events (leaked header value), `fs` events (SharedPreferences
  value), or `custom` events (a debug log line) — see "Secret/credential
  leak detection" below for the full design.
- **Vulnerability Detection (`insecure_intent`, `insecure_sql_query`, `insecure_webview`, `weak_biometric`)**:
  - Catches implicit intents leaking data or granting broad permissions (`intent` kind).
  - Detects unparameterized SQL queries utilizing suspicious injection substrings (`sql` kind).
  - Flags insecure WebView configurations such as Javascript Interfaces, File Access, and Mixed Content (`webview` kind).
  - Flags Biometric Prompt usage that lacks a CryptoObject (`biometric` kind).

Deliberately excluded: TLD-based host blocklisting (flagging `.ru`/
`.tk`/`.xyz` domains). It's a common heuristic in security tooling, but a
weak one — huge numbers of legitimate services use those TLDs, and it
teaches nothing about actual behavior. Left out on purpose, documented in
`rules.go`, not a gap.

Verified end-to-end (not just unit-tested in isolation) that rules
actually add value beyond what novelty alone catches: in the same smoke
test used to calibrate the scorer, two of the three `first_seen_host`
flags fired on events scoring 0.33 and 0.31 — comfortably *under* the 0.5
novelty threshold, meaning novelty scoring alone would have missed them.
This is the complementary-detection design working as intended, not a
hypothetical.

The dashboard (`web/index.html`) shows rule matches as badges next to the
NCD score, in both the event log and the flagged drawer — red for
`weak_cipher`/`sensitive_path`/`first_seen_host`/`secret_leak`, blue for
the informational `app_updated`, violet for `compressor_disagreement`
(ambiguous — the two independent measurements disagree, not a confirmed
finding either way). An event flagged only by a rule (low NCD, real
pattern match) is now visibly explained rather than just showing a low
number with no context for why it's in the flagged list.

## What's real vs. what needs tuning

Built and verified with tests (`go test ./...`, all passing):
- WAL: crash-recovery tested against a truncated tail write (simulated
  power-loss mid-append) — recovers cleanly, sequence numbers stay correct.
- Multi-source isolation: verified two different apps' baselines don't
  bleed into each other.
- Dashboard (`web/index.html`, served by driftnetd at `/`): live
  per-source NCD seismograph, event log, flagged-events drawer with
  triage text. Polls the JSON API, no build step.

**The novelty scorer went through three real revisions**, each caught by
actually running the pipeline end-to-end against synthetic traffic rather
than trusting the math on paper. Full detail lives in
`internal/novelty/ncd.go`'s package doc; short version:

1. Textbook NCD (comparing a single event against the whole concatenated
   baseline) drifted toward 1 purely as the baseline window filled,
   independent of similarity — wrong denominator for a size-mismatched
   comparison.
2. The fix (marginal-cost diffing: `C(baseline+payload) - C(baseline)`)
   fixed the drift but introduced compressor block-boundary noise that
   *also* scaled with baseline size — a controlled test on stationary
   synthetic traffic showed the score drifting from 0.53 to 0.87 over 100
   events with zero actual change in the data.
3. Replaced the diff with dictionary-assisted single-shot compression
   (zstd's raw prefix-dictionary mode): score payload once, using the
   baseline as compression context, instead of compressing two separate
   buffers and subtracting. A controlled test confirmed this stays flat
   (0.250 mean at 40 events, 0.250 mean at 100 events, not just "close" —
   identical) as the baseline grows.

Separately, magnitude anomalies (a byte count going from 341 to 4.8M)
were invisible to the compressor because the event's lexical *shape*
barely changes — fixed with `internal/fingerprint`, a generic log10
magnitude-bucketing preprocessor that runs before scoring (never before
storage — the WAL keeps the untouched original).

**Final calibration**, from an end-to-end smoke test (WS ingest -> WAL ->
scorer -> flag threshold -> dashboard API, all real code, no mocks) with
60 baseline events and 3 injected anomalies: steady-state traffic scores
0.20-0.28, a DES/ECB cipher swap scores 1.0, a write to a suspiciously-
named file scores 0.93, and the 4.8MB exfil-shaped POST — the case that
was flat-out missed (0.27) two revisions ago — now scores 0.55 and gets
flagged. All 3 injected anomalies are caught at threshold 0.5, with a
clean margin over baseline noise.

Also found and fixed along the way: the dashboard's flagged-events
endpoint had its own hardcoded 0.55 threshold, completely independent of
the ingest server's trigger threshold — the two drifted apart the moment
the trigger threshold got recalibrated, so an event could get sent for
LLM triage but never show up in the flagged list. Now both read from one
value (`ingest.NoveltyThreshold`, passed into the API handlers at
startup), so they can't silently diverge again.

Test coverage: 75 tests across 8 packages (`api`, `attribution`,
`fingerprint`, `ingest`, `novelty`, `rules`, `store`, `triage`), all
passing with `-race`, verified stable across repeated fresh runs
(`-count=1`). `ingest`'s tests are real WebSocket round trips through
`httptest` against a real WAL and real scorer — no mocks. `triage`'s
tests are the first this package has ever had: a mock Ollama-shaped HTTP
server, because the real thing had never once run during any earlier
smoke test in this sandbox (every `-ollama` flag pointed at a URL nothing
was listening on) — the request/response code path was written, looked
correct, and was completely unverified until these tests existed.

## Cold-start fix: warmup gating on `first_seen_host`

`rules.Config.WarmupEvents` fixes a real usability problem: instrumenting
a real app for the first time can legitimately mean contacting dozens of
hosts (CDNs, API endpoints, ad SDKs) within seconds — completely normal
startup behavior that, without this gate, floods the flagged view with
"first seen" hits for everything at once. A source's host-seen state
still builds up silently during warmup (so hosts contacted during the
flood don't spuriously re-flag once warmup ends), only the *match* is
gated. Zero value means no warmup (matches the rule's original always-on
behavior) — a deliberate choice, not a missing default, so a bare
`Config{}` never silently under-flags. Production wires
`DefaultWarmupEvents` (40) explicitly at the call site.

## Feature attribution: a real bug in the first version, found by testing it live

`internal/attribution` answers "which field actually drove this event's
novelty score" via leave-one-field-out re-scoring: blank one JSON field
at a time (type-preserving zero value, not deletion — see below), re-score
the variant, see how much the score drops. Cheap, single-pass
approximation of a Shapley-value-style attribution, using compression
cost as the value function.

**The first implementation shipped with two real bugs, both found by
testing against realistic conditions instead of trusting a clean unit
test:**

1. **Masking strategy.** Deleting a field's key entirely changes the
   object's arity (4 keys instead of 5), and a baseline trained on 5-key
   events treats ANY 4-key object as structurally novel — independent of
   which key is missing. A controlled measurement showed this alone
   inflated a byte-identical field's ("transport", present verbatim in
   every single event) score by +0.071 when it should have contributed
   ~0. Fixed by replacing the field's value with a type-preserving zero
   value instead of deleting the key — same arity, only that field's
   content changes. The same measurement showed this roughly halves the
   confound (0.071 → 0.034) but doesn't eliminate it; `Delta` is
   documented as a directional signal, not an exact measurement.

2. **Baseline staleness — the more serious one.** The first version
   exposed attribution as a lazy, on-demand API endpoint, computed
   whenever someone clicked to view it. That meant scoring masked
   variants against whatever the *live* baseline happened to be at
   request time — but by then, the real ingest pipeline had already
   folded the very event being explained (plus anything that arrived
   after it) into that same baseline. Every masked variant ended up
   compared against a baseline that already contained an exact copy of
   the original, collapsing every field's delta toward the same small,
   meaningless number. Caught by running the full smoke test end-to-end
   (not just the isolated unit test, which used a clean, never-folded
   baseline and looked perfect) and noticing the top-attributed field for
   a real flagged event was "transport" — a field that's byte-identical
   in every event, baseline and anomaly alike. That result should have
   been disqualifying on sight, not something to explain away.

   Fixed by restructuring the ingest path itself: `novelty.Manager` now
   exposes `PeekScore` (score without folding) and `Observe` (fold
   without scoring) as explicit separate steps, instead of one atomic
   `ScoreEvent`. Attribution now runs eagerly, at ingest time, against
   the exact pre-fold snapshot that produced the original score — then
   the real event gets folded in. Attribution is stored directly on the
   event (`Attribution` field, alongside `NCDScore` and `RuleMatches`)
   rather than queried later; the separate `/api/events/{seq}/attribution`
   endpoint from the first version is gone entirely; the dashboard reads
   `ev.attribution` directly, no extra fetch.

   Re-running the exact same live smoke test after the fix: the
   exfil-shaped anomaly (unfamiliar host, 4.8MB body) now correctly shows
   `host` as the top-attributed field (+0.117), matching the isolated
   unit test almost exactly, with `transport`/`method`/`request_bytes`
   sitting at a small negative residual (-0.02 to -0.04) — the expected,
   documented leftover from fix #1, not the dominant signal it was before.

## Per-kind baseline scoping, and two more restart bugs found alongside it

The secondary limitation flagged above — one source's baseline mixing
network, crypto, and filesystem events together, making attribution
uninformative for a kind's first occurrence — is fixed.
`novelty.Manager` itself didn't change: it already just keys baselines by
whatever string a caller passes in. The fix is entirely in the caller:
`ingest.ScoringKey(device, app, kind)` now builds a kind-qualified key,
so each event kind gets its own isolated rolling window. Rules
(`first_seen_host`) deliberately still use the plain `device:app` key —
hosts only ever appear in `network`-kind events, so there's no
cross-kind contamination to fix there.

Verified two ways, not just unit-tested against a mock:

- **The single-shot smoke test doesn't actually prove the fix** — a
  source's very first `crypto` event will always score 1.0 with all-zero
  attribution regardless of whether kind-scoping works, because there's
  no baseline at all yet, same as any source's genuine first event.
  Realizing this mid-verification led to a second, proper test: establish
  30 `network` events AND a real 20-event `crypto`-only baseline, then
  inject a weak-cipher anomaly. Before this fix, that baseline would have
  been pooled with the unrelated network traffic; after it, attribution
  correctly ranks `transformation` as the top-attributed field within the
  isolated crypto baseline — something that was impossible to test
  meaningfully before, since there was no way to build an isolated
  same-kind baseline at all. (The signal here is noisier than the network
  case — smaller baseline, and an incidental compressor quirk where the
  anomalous `"56"` is literally a substring of the baseline's `"256"`,
  so blanking it can look *more* novel than keeping it. Documented in
  `attribution_test.go`, not hidden.)

**Reviewing the WAL-replay warmup path to update its key construction for
this change surfaced two more real, previously-unverified bugs** — every
smoke test up to this point used a fresh empty data directory, so the
"restart with existing history" path had zero live testing:

1. Replay warmup scored raw `ev.Detail`, not `fingerprint.Enrich(ev.Detail)`
   — inconsistent with live ingest, which always scores the enriched
   fingerprint. A restart would have warmed baselines with a different
   byte representation than live events get compared against.
2. `rules.Evaluator`'s state (seen-hosts, warmup event counts) wasn't
   persisted or rebuilt at all. Every restart would start it completely
   fresh — meaning every previously-known host would flood as
   "first seen" again, forever, on every single restart.

Fixed both: replay warmup now uses `ingest.ScoringKey` +
`fingerprint.Enrich`, matching live ingest exactly, and
`rules.Evaluator.ObserveOnly` rebuilds seen-hosts/warmup state from
history without emitting matches for events that already happened.
Verified with an actual process kill and restart against real WAL data
(not a mock): establish a known host, kill `driftnetd`, restart it
against the same data directory, re-contact the same host. Zero flags —
confirming both the novelty baseline and rules state actually survive a
restart now, rather than trusting that the code change was correct
because it compiled and passed isolated unit tests.

Not yet built:
- Per-app allowlisting / auto-baseline-reset when you knowingly change an
  app's normal behavior (e.g. after an app update)
- iOS-side hooks (frida works on the 14 Pro too if jailbroken, but yours
  isn't — this is Android-only for now, which is fine since the 9R is the
  rooted device anyway)

## App-update diffing: the first extension idea, finally built

Identified early on as the single highest-value extension since it costs
almost nothing on top of what already exists: `agent/hooks.js` now
resolves the target app's `versionName:versionCode` once per attach
(`resolveAppVersion`, run inside `Java.perform` since it needs real JVM
reflection, unlike the lighter `Application.identifier` used for the
package name) and stamps it on every event. `rules.Evaluator` tracks the
last-seen version per source and fires an `app_updated:<old>-><new>`
match — visibly distinct in the dashboard (blue "info" badge, not red —
it's informational, not a security concern by itself) — the moment a new
version shows up mid-session.

This is the feature that makes driftnet useful for more than pure
security monitoring: point it at an app you maintain across releases, and
"did the new build start doing something different" becomes a visible,
timestamped event instead of something you'd only notice by accident.
Real bug caught while building the test for this, not a hypothetical:
`OnFlagged` runs in a spawned goroutine
(`go s.OnFlagged(ev)` in `ingest/server.go`), decoupled from the
synchronous per-event `OnEvent` callback. An early version of the
end-to-end test waited on "4 events processed" (via `OnEvent`) before
checking for the version-change flag, which passed on the first run and
failed on the very next one with identical code — because reaching
`eventCount >= 4` says nothing about whether that 4th event's
*asynchronous* `OnFlagged` call has actually finished appending to the
flagged list yet. Fixed by waiting on the actual condition the assertion
depends on (`len(flagged) >= 2`), confirmed stable across 5 repeated
fresh runs afterward.

## Testing a real Play Store app (not one built from source)

The concrete use case this was built for: pointing driftnet at your own
company's published app, which you have legitimate access to as a
developer on it — standard dynamic-analysis practice (see OWASP's Mobile
Security Testing Guide), not something requiring special new tooling
beyond what's here. A few things are different from testing an app built
locally from source:

**Check this before anything else: is the app Flutter?** An APK is just
a zip file, so pull it (`adb shell pm path <package>` gives the on-device
path, then `adb pull`) and check:
```bash
unzip -l app.apk | grep libflutter.so
```
Non-empty output means every network hook in this project (`hookOkHttp3`,
`hookJavaNet`) sees **zero** traffic — Flutter routes networking through
Dart's own stack, bypassing OkHttp entirely, not a coverage gap but a
complete blind spot. See "Deep-research pass" above for the full account
and the best-effort (unverified) `hookFlutterHttpClient` this led to.
Crypto, filesystem, SharedPreferences, and logging hooks are unaffected
either way — this is specifically a network-visibility question.

**Finding the real package name.** The Play Store URL's `id=` parameter
is the package name directly (`play.google.com/store/apps/details?id=`
**this part**). Or, with the app already installed on the test device:
`adb shell pm list packages | grep -i <name>`.

**Obfuscation (ProGuard/R8) mostly doesn't matter here.** It renames the
*app's own* classes, not the Android standard library or common
libraries the hooks actually target — `okhttp3.RealCall`,
`javax.crypto.Cipher`, `java.security.MessageDigest`,
`java.io.FileOutputStream`, `android.app.SharedPreferencesImpl$EditorImpl`,
`android.util.Log` are all framework or common-library classes that keep
their real names even in a fully obfuscated release build. This was a
deliberate hook design choice from the start, not a fix — targeting
app-internal (obfuscated) class names would make the agent fragile
across every single release.

**Basic tamper/root detection, if present.** Set
`ENABLE_ANTI_DETECTION_BYPASS = true` in `agent/hooks.js` only if the app
force-closes or misbehaves under Frida. The bypasses included
(`Debug.isDebuggerConnected`, a narrowly-scoped `File.exists` override for
specific known root-indicator paths) cover the common, simple cases. A
commercial RASP/mobile-app-protection SDK would need targeted, app-
specific research beyond what's pre-built here — that's genuinely a
different, deeper task, not a gap in this tool.

**Tracking releases over time.** Every event now carries `app_version`.
Running the relay against consecutive Play Store releases of the same
app, the dashboard will show an `app_updated` badge the first time a new
version's traffic shows up — that's the whole feature from the section
above, just applied to real release cadence instead of a synthetic
version bump.

**Scope reminder:** everything above stays on your own test device
against your own account, observing metadata only (see "Why compression
instead of a trained classifier" above) — no interference with the live
service or its other users, no traffic interception beyond what the
app's own process already handles internally.

## A full audit pass, and why it mattered more than another feature

At a certain point, the highest-value thing wasn't another feature built
against synthetic data — it was going back through everything already
built and actually checking it still hangs together, since a lot had
accumulated incrementally (`ScoringKey`, rules warmup config, app_version
threading through four different layers). Found four real things,
none of them hypothetical:

**1. A genuine `send()` naming collision risk in `agent/hooks.js`.**
The original code wrapped Frida's native `send` like this:
`function send(payload) { send_(payload); } const send_ = globalThis.send;`
— reasoning that capturing the original before anything could shadow it
would be safe. Testing this exact pattern in Node.js confirmed it works
there, but only because Node wraps each file in a CommonJS module
function, scoping top-level `function` declarations locally rather than
binding them onto the true global object. Frida's own docs describe its
core globals (including `send`) as installed via
`Object.defineProperties(globalThis, {...})`, and default property
descriptors from that API are non-writable/non-configurable unless
specified otherwise — combined with this file's `'use strict'` mode, a
redeclared `send` could theoretically throw immediately at script load,
or silently recurse forever, depending on exactly how Frida's script
execution model handles it. I don't have access to real Frida from this
sandbox to test the actual behavior, and the failure mode if I'd guessed
wrong is severe (total agent failure on the very first real run, hard to
diagnose from Frida's console output alone). Fixed by removing the naming
collision entirely (`NATIVE_SEND` / `emitToRelay`), which is safe
regardless of which execution model turns out to be correct — verified
against the worst case (non-writable, non-configurable global) directly.

**2. A real, previously-unverified data race.** `main.go`'s `OnFlagged`
callback used to mutate `ev.Triage = note` directly on a `*store.Event`
pointer already sitting in the dashboard API's in-memory event ring —
with zero synchronization against `RecentEvents`/`FlaggedEvents`
concurrently reading that same field while iterating under
`h.mu.RLock()`. A `RWMutex` only protects goroutines that actually
acquire it; a goroutine mutating a field through an independent pointer,
never touching that mutex, isn't covered at all. No existing test caught
this — `ingest` package tests never construct a `Handlers`, and `api`
package tests never mutated a pushed event concurrently with reading it.
A standalone reproduction (isolated from this codebase, same shape)
confirmed `-race` genuinely flags the old pattern as a data race. Fixed
with `Handlers.SetTriage`, which routes the mutation through the same
lock that protects reads. **Worth remembering generally: a green,
race-clean test suite proves the paths your tests exercise are race-free
— not that no race exists anywhere in the program.** 59 passing tests
with `-race` didn't catch this because none of them exercised this
specific cross-goroutine mutation pattern; it took a manual, non-test-
driven read-through of the actual production wiring to find it.

**3. Three instances of documentation drift**, all in `README.md`: the
architecture diagram was missing `rules/` and `attribution/` entirely
(both added well after the diagram was first drawn); the rules-engine
section said "three rules" and "red badges" after a fourth rule
(`app_updated`) with a deliberately different (blue, informational)
badge color had already been added; and a code comment referenced
"Duktape/V8" as Frida's JS runtime, which was replaced by QuickJS back in
Frida 14 — stale relative to this project's actual Frida 17.15.3 target.
None of these affected runtime behavior, but all of them would have
actively misled a future reader (including me, next session) about the
system's real shape.

None of this was found by writing more tests against more synthetic
scenarios. It was found by reading the actual code and actual docs
critically, the same way a second reviewer would before calling
something done.

## A second, independent compressor: catching what one alone can't

Every detection mechanism up to this point (zstd novelty scoring, the
four rules) shares one blind spot: they're each a single measurement.
`internal/novelty/secondary.go` adds a genuinely different kind of
signal -- not "is this event novel," but "do my two independent novelty
measurements agree with each other."

**Grounded empirically before building anything, not assumed.** zstd and
DEFLATE (Go's standard library `compress/flate`) are both LZ77-family
compressors, but differ enough in match-finding and entropy coding (zstd:
larger practical window, FSE/tANS; DEFLATE: hard 32KB window, Huffman)
that a standalone experiment showed them giving meaningfully different
readings on the same synthetic redundant-vs-anomalous pair used
throughout this project: zstd separated the two by 0.380 (0.245 -> 0.625),
DEFLATE by 0.429 (0.130 -> 0.559) -- same direction, different magnitude.
That gap is confirmed to reproduce in the real code
(`TestPrimaryAndSecondaryScorers_CanGenuinelyDisagree`), not just the
throwaway script.

**Built as a fully separate implementation, not a refactor.** The
primary `Scorer` has three real revisions behind it (see `ncd.go`), each
found only after significant testing investment. Extracting it into a
pluggable-compressor interface to add DEFLATE support would risk
disturbing that hard-won correctness for an optional secondary feature.
`SecondaryScorer`/`SecondaryManager` duplicate the dict-assisted ratio
mechanism independently instead -- more code, but zero risk to the
existing, load-bearing primary path. (Considered brotli first, for a more
architecturally distinct third opinion -- its public Go API only exposes
brotli's own built-in static dictionary, not a custom-prefix API like
zstd's, so replicating the dict-assisted approach with it would have
meant reverting to the "diff two full compressions" technique already
found to be noisy and fixed once. DEFLATE's stdlib `NewWriterDict` does
support a real custom prefix, which is why it was chosen instead.)

**The signal itself is narrow by design:** `compressor_disagreement`
fires only when the two scores land on *opposite sides* of their
respective thresholds -- not "the scores differ by some amount," which
synthetic testing showed happens on ~0.07-0.12 baseline noise even for
ordinary traffic. The specific case this catches (one measurement flags,
the other doesn't) is architecturally invisible to any single-compressor
system, however well-tuned.

**Found a real, unrelated bug while searching for a live disagreement
case to test against.** An RSA/ECB/OAEPWithSHA-256AndMGF1Padding cipher
call -- a modern, *recommended* RSA configuration -- was matching the
existing `weak_cipher` rule's `/ecb/` pattern purely on substring
coincidence: Java's transformation-string convention uses "ECB" as an RSA
padding-scheme placeholder, not a genuine block-cipher mode the way it is
for AES or DES. Fixed by excluding RSA's ECB-placeholder usage from that
specific pattern, while adding a new, more precise pattern
(`pkcs1padding`) that still correctly catches the *actual* legacy-RSA
weakness (PKCS1v1.5 padding, vulnerable to Bleichenbacher-style attacks)
that the old imprecise check was conflating with RSA-OAEP's incidental
"ecb" substring. Three tests lock in: OAEP not flagged, legacy PKCS1
still flagged, ordinary AES/ECB still flagged (the exclusion is
RSA-specific, not a general weakening of the rule).

The end-to-end disagreement test itself (`TestHandleWS_
CompressorDisagreementFlagsThroughRealPipeline`) uses a specific payload
found by empirical search against the *actual* production pipeline
(fingerprint-enriched, per-kind-baseline-keyed, real thresholds) rather
than a hand-picked case from the simplified standalone experiment --
`RSA/ECB/OAEPWithSHA-256AndMGF1Padding` after an AES/GCM baseline lands
primary at 0.535 (crosses) and secondary at 0.412 (doesn't).

## Secret/credential leak detection: on-device, redacted before it ever leaves

Weak ciphers and sensitive file paths were already covered; hardcoded API
keys and tokens leaking into `SharedPreferences`, debug logs, or request
headers were not, despite being one of the most common real findings in
mobile security work. Closed by adding a client-side secret scanner
(`agent/hooks.js`) wired into three hook points, plus a new
`secret_leak` rule (`internal/rules`) that reads only a redacted
indicator, never the actual value.

**The detection has to happen on the phone, not on the laptop, and this
isn't a stylistic choice.** If a real secret were transmitted to
driftnetd "for redaction on the way in," that would create a *second*
copy of the leak — sitting in the WAL and the dashboard's browser
session — which is worse than not detecting it at all. `scanForSecrets`
runs entirely in the Frida agent, before `emit()` is ever called; only a
pattern name and a short, non-reversible preview (a handful of leading
characters plus length) cross the wire. The full secret value never
touches the relay, the WAL, or the dashboard.

**Detection covers known vendor formats** (AWS access keys, Google API
keys, Slack tokens, Stripe live keys, GitHub tokens, generic Bearer
tokens, JWTs, PEM private key headers) **plus a generic high-entropy
fallback** for secrets that don't match a known format — a long,
random-looking string assigned somewhere a secret would plausibly live.

**Wired into three hook points**, each catching a different real leak
vector:
- `hookOkHttp3` scans request header *values* (Authorization, X-API-Key,
  custom auth headers — a very common place tokens appear)
- `hookSharedPrefs` scans the *value* being written (apps storing API
  keys in SharedPreferences instead of the Android Keystore is a
  frequent, well-known finding)
- `hookLogging` (new) scans `Log.d/e/w/i/v` messages — the classic
  "forgot to remove `Log.d(TAG, "token=" + token)` before shipping"
  vector. Deliberately does NOT emit on every log call the way other
  hooks emit on every event: log output is highly variable free text
  with near-zero baseline value, so this hook only emits when
  `scanForSecrets` actually finds something.

**A real false positive found by testing the heuristic, not trusting it
on paper.** The generic high-entropy fallback initially flagged some
UUIDs and not others — two structurally identical UUID-v4 strings,
differing only in which hex digits happened to repeat, gave inconsistent
results. Root cause: hex is already a 16-symbol alphabet, so a UUID's
theoretical maximum entropy sits right at the threshold being checked,
making the outcome a coin flip on specific digit content rather than a
real signal. UUIDs are extremely common in mobile apps (session/device/
correlation IDs) and inconsistent flagging would have been a genuinely
confusing source of noise. Fixed two ways at once: an explicit UUID-shape
exclusion, plus the more general fix behind it — requiring the fallback
heuristic to see both upper *and* lower case characters, since real
secrets (API keys, tokens) are almost always mixed-case/base64-like,
while lowercase-only hex (UUIDs, MD5/SHA1 digests, other IDs) is common
and not a secret. Verified against 20 randomly generated UUIDs after the
fix, all clean, plus the original 9 real-secret-format test cases still
correctly matching.

## Deep-research pass: comparing against the real state of the art

Rather than keep adding features against synthetic data, this pass
compared driftnet against OWASP's Mobile Application Security Testing
Guide (MASTG) — the actual industry-standard reference for what mobile
dynamic analysis covers — and the broader Frida/mobile-security
literature, specifically looking for gaps rather than more ideas to
brainstorm.

### The one that actually matters: Flutter apps may be invisible to every network hook

**Found, not assumed:** MASTG lists "Intercepting Flutter HTTPS Traffic"
as its own separate technique from standard Android interception,
because it's a genuinely different problem. Flutter apps route
networking through Dart's own `HttpClient`, backed by BoringSSL statically
linked into `libflutter.so`, instead of the Android system's
OkHttp/HttpURLConnection stack that `hookOkHttp3` and `hookJavaNet`
target. Flutter also doesn't use the system's certificate store or proxy
settings — traffic bypasses the OS network layer almost entirely. The
practical consequence: if a target app is built with Flutter, the
existing network hooks don't have *reduced* coverage, they have **zero**
coverage — nothing to do with obfuscation or hook reliability, the
traffic simply never passes through the code being hooked.

**Given Upjaoo's app uses LiveKit** (which ships official Flutter and
React Native SDKs, both common choices for a multi-feature cross-platform
app), this isn't a hypothetical edge case to dismiss — it's a real
question worth answering before assuming any network-layer finding from
a real run means anything.

**The one-command check, before trusting any of this:** an APK is just a
zip file, so:
```bash
unzip -l app.apk | grep libflutter.so
```
Non-empty output means the app is Flutter. (React Native is generally
*not* subject to this problem — its networking typically does route
through the standard Android stack, so the existing hooks should apply
normally there.)

**What was added:** `hookFlutterHttpClient` in `agent/hooks.js`, a
best-effort attempt at the same metadata capture (method + host) via
`dart:io.HttpClient.open`, which one source showed as directly reachable
through Frida's ordinary `Java.use()` bridge. **Marked clearly as
unverified** in the code and here: that source wasn't an authoritative
Frida/Dart reference, and this build environment has no way to test it
against a real Flutter app. Wrapped in try/catch like every other hook,
so it silently no-ops if it doesn't apply.

**What was deliberately NOT attempted:** full TLS/certificate-pinning
bypass for Flutter. The literature is consistent and detailed about what
this actually requires — reverse-engineering a stripped `libflutter.so`
binary in Ghidra to locate `ssl_crypto_x509_session_verify_cert_chain`
inside BoringSSL by pattern-scanning for string references, since no
symbols survive compilation. That's a real, substantial reverse-
engineering project in its own right, not a quick addition — and doing
it would mean decrypting full payload content, crossing the metadata-only
design boundary this entire agent has committed to from the start (see
"Why compression instead of a trained classifier" above). If Upjaoo's
app turns out to be Flutter and the best-effort hook above doesn't give
enough signal, that's the honest next decision to make, not something to
pre-build blindly.

### Secondary gaps found, not built (real, but lower-priority than the above)

- **SQLite database content.** MASTG's storage-testing checklist covers
  Shared Preferences, SQLite databases, and general internal/external
  storage together as one category; driftnet only covers the first.
  Apps caching tokens or user data in a local SQLite database (very
  common, e.g. via Room) have zero coverage here.
- **Deep link / Intent handling.** MASTG has a dedicated technique
  ("Monitoring Deep Link Handlers at Runtime with Frida") for this
  Android-specific attack surface — a distinct category from anything
  currently hooked.
- **Native/JNI-level instrumentation.** Every hook here operates at the
  Java/Kotlin layer via `Java.perform`/`Java.use`. An app doing
  networking or crypto through NDK native code (common for performance-
  sensitive or cross-platform-native libraries) would be invisible to all
  of it — would need Frida's `Interceptor.attach` on native library
  exports instead, a different technique entirely.

None of these three were built this pass. Building them without a real
target to validate against would repeat the exact mistake this whole
project has tried to avoid: adding detection surface for problems that
might not exist in the actual app, instead of the ones that do.

## Scope and intent

This instruments **apps you own, on your own rooted device, for your own
security research** — inspecting what your own installed apps actually do
at runtime. It is not built or intended for intercepting third-party
traffic you don't have rights to inspect.
