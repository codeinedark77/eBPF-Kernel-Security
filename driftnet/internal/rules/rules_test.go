package rules

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestEvaluate_WeakCipherDetectsECB(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"DES/ECB/NoPadding"}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if !contains(matches, "weak_cipher") {
		t.Fatalf("expected weak_cipher match, got %v", matches)
	}
}

func TestEvaluate_StrongCipherDoesNotMatch(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"AES/GCM/NoPadding"}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if contains(matches, "weak_cipher") {
		t.Fatalf("AES/GCM should not match weak_cipher, got %v", matches)
	}
}

func TestEvaluate_WeakCryptoScopedToCryptoKindOnly(t *testing.T) {
	// A "des" substring in an unrelated field of a non-crypto event must
	// not trigger the rule -- it's scoped to kind=="crypto" specifically.
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"host":"designer-assets.example.com","path":"/v1/sync"}`)
	matches := e.Evaluate("dev:app", "network", detail, nil)
	if contains(matches, "weak_cipher") {
		t.Fatalf("weak_cipher should not fire on non-crypto events, got %v", matches)
	}
}

func TestEvaluate_SensitivePathDetectsContactsDump(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"write_open","path":"/data/data/com.example.app/files/contacts_dump.db"}`)
	matches := e.Evaluate("dev:app", "fs", detail, nil)
	if !contains(matches, "sensitive_path") {
		t.Fatalf("expected sensitive_path match, got %v", matches)
	}
}

func TestEvaluate_OrdinaryPathDoesNotMatch(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"write_open","path":"/data/data/com.example.app/cache/thumbnail_12.png"}`)
	matches := e.Evaluate("dev:app", "fs", detail, nil)
	if contains(matches, "sensitive_path") {
		t.Fatalf("ordinary cache path should not match, got %v", matches)
	}
}

func TestEvaluate_FirstSeenHostFiresOnceThenNotAgain(t *testing.T) {
	e := NewEvaluator(Config{})
	d1 := json.RawMessage(`{"host":"api.example.com","path":"/v1/sync"}`)

	m1 := e.Evaluate("dev:app", "network", d1, nil)
	if !contains(m1, "first_seen_host") {
		t.Fatalf("first sighting of a host should flag first_seen_host, got %v", m1)
	}

	m2 := e.Evaluate("dev:app", "network", d1, nil)
	if contains(m2, "first_seen_host") {
		t.Fatalf("second sighting of the same host should not re-flag, got %v", m2)
	}
}

func TestEvaluate_FirstSeenHostIsolatedPerSource(t *testing.T) {
	e := NewEvaluator(Config{})
	d := json.RawMessage(`{"host":"api.example.com"}`)

	e.Evaluate("dev:appA", "network", d, nil)
	// Different source (different app) should see this host as new too --
	// host-seen state must not leak across apps, same isolation guarantee
	// novelty.Manager gives per-source baselines.
	m := e.Evaluate("dev:appB", "network", d, nil)
	if !contains(m, "first_seen_host") {
		t.Fatalf("host state leaked across sources: appB should see api.example.com as new, got %v", m)
	}
}

func TestEvaluate_MalformedDetailReturnsNoMatchesNotError(t *testing.T) {
	e := NewEvaluator(Config{})
	matches := e.Evaluate("dev:app", "crypto", json.RawMessage(`not json`), nil)
	if matches != nil {
		t.Fatalf("malformed detail should return nil matches, got %v", matches)
	}
}

func TestEvaluate_UnknownKindProducesNoMatches(t *testing.T) {
	e := NewEvaluator(Config{})
	matches := e.Evaluate("dev:app", "ipc", json.RawMessage(`{"anything":"goes"}`), nil)
	if matches != nil {
		t.Fatalf("unknown kind should produce no matches (no rules defined for it), got %v", matches)
	}
}

func TestEvaluate_WarmupSuppressesFloodOfFirstSeenHosts(t *testing.T) {
	e := NewEvaluator(Config{WarmupEvents: 10})

	var matches int
	for i := 0; i < 10; i++ {
		// 10 distinct hosts, all during the warmup window -- this is
		// exactly the real scenario that motivated the fix: a freshly
		// instrumented app's startup burst contacting many hosts at
		// once, none of which should flood the flagged view.
		host := fmt.Sprintf("host%d.example.com", i)
		d := json.RawMessage(fmt.Sprintf(`{"host":%q}`, host))
		m := e.Evaluate("dev:app", "network", d, nil)
		matches += len(m)
	}
	if matches != 0 {
		t.Fatalf("expected zero first_seen_host matches during warmup (10 events, warmup=10), got %d", matches)
	}
}

func TestEvaluate_FirstSeenHostResumesAfterWarmup(t *testing.T) {
	e := NewEvaluator(Config{WarmupEvents: 3})

	// Burn through warmup with 3 events (none should match -- count
	// reaches exactly warmupEvents, still gated).
	for i := 0; i < 3; i++ {
		host := fmt.Sprintf("warmup-host%d.example.com", i)
		e.Evaluate("dev:app", "network", json.RawMessage(fmt.Sprintf(`{"host":%q}`, host)), nil)
	}

	// 4th event: warmup cleared (count=4 > warmupEvents=3), and this is
	// a genuinely new host -> should match.
	m := e.Evaluate("dev:app", "network", json.RawMessage(`{"host":"post-warmup.example.com"}`), nil)
	if !contains(m, "first_seen_host") {
		t.Fatalf("expected first_seen_host to fire once warmup clears, got %v", m)
	}
}

func TestEvaluate_HostsSeenDuringWarmupDontReflagAfter(t *testing.T) {
	// The subtle part of the fix: a host contacted DURING warmup must be
	// silently recorded, so it doesn't spuriously "become new again" the
	// moment warmup ends. If this weren't true, every host from the
	// startup burst would all flag at once on the first post-warmup
	// event, which is arguably worse than the original flood.
	e := NewEvaluator(Config{WarmupEvents: 2})

	e.Evaluate("dev:app", "network", json.RawMessage(`{"host":"api.example.com"}`), nil) // count=1, gated
	e.Evaluate("dev:app", "network", json.RawMessage(`{"host":"cdn.example.com"}`), nil) // count=2, gated

	// count=3 > warmupEvents=2 -> warmed up. Re-contact api.example.com,
	// already seen during warmup -- must NOT flag.
	m := e.Evaluate("dev:app", "network", json.RawMessage(`{"host":"api.example.com"}`), nil)
	if contains(m, "first_seen_host") {
		t.Fatalf("host seen during warmup should not re-flag once warmup ends, got %v", m)
	}
}

func TestEvaluate_ZeroWarmupMatchesOriginalAlwaysOnBehavior(t *testing.T) {
	// Config{} (zero value) must behave exactly like the rule did before
	// the warmup gate existed: first sighting flags immediately. This is
	// a deliberate design choice (see Config doc), not an oversight, and
	// this test locks it in.
	e := NewEvaluator(Config{})
	m := e.Evaluate("dev:app", "network", json.RawMessage(`{"host":"api.example.com"}`), nil)
	if !contains(m, "first_seen_host") {
		t.Fatalf("zero-value Config should flag on first sighting immediately, got %v", m)
	}
}

func TestEvaluate_WarmupCountedPerSourceIndependently(t *testing.T) {
	e := NewEvaluator(Config{WarmupEvents: 5})

	// Source A gets 5 events (still gated, count never exceeds 5).
	for i := 0; i < 5; i++ {
		e.Evaluate("dev:appA", "network", json.RawMessage(fmt.Sprintf(`{"host":"a%d.example.com"}`, i)), nil)
	}
	// Source B, brand new, should independently be gated too -- warmup
	// state must not leak across sources any more than seenHosts does.
	m := e.Evaluate("dev:appB", "network", json.RawMessage(`{"host":"first.example.com"}`), nil)
	if contains(m, "first_seen_host") {
		t.Fatalf("source B's warmup should be independent of source A's progress, got %v", m)
	}
}

func TestObserveOnly_RebuildsWarmupCountFromHistory(t *testing.T) {
	e := NewEvaluator(Config{WarmupEvents: 3})

	// Simulate replaying 5 historical events on startup.
	for i := 0; i < 5; i++ {
		e.ObserveOnly("dev:app", "network", json.RawMessage(fmt.Sprintf(`{"host":"h%d.example.com"}`, i)), "")
	}

	// A genuinely new host, post-replay: warmup (3) should already be
	// cleared from the 5 replayed events, so this should flag immediately
	// -- exactly as it would have live, before any restart happened.
	m := e.Evaluate("dev:app", "network", json.RawMessage(`{"host":"new.example.com"}`), nil)
	if !contains(m, "first_seen_host") {
		t.Fatalf("expected first_seen_host to fire immediately post-replay (warmup already cleared by history), got %v", m)
	}
}

func TestObserveOnly_RebuildsSeenHostsFromHistory(t *testing.T) {
	e := NewEvaluator(Config{WarmupEvents: 0}) // no warmup gate, isolate the seen-hosts behavior

	e.ObserveOnly("dev:app", "network", json.RawMessage(`{"host":"api.example.com"}`), "")

	// Re-contacting a host that was already recorded via ObserveOnly
	// (i.e. it was in the WAL from before a restart) must NOT flag as
	// first-seen -- that's the whole point of replaying history before
	// accepting live traffic.
	m := e.Evaluate("dev:app", "network", json.RawMessage(`{"host":"api.example.com"}`), nil)
	if contains(m, "first_seen_host") {
		t.Fatalf("host already observed via ObserveOnly (replay) should not re-flag live, got %v", m)
	}
}

func TestObserveOnly_NonNetworkKindOnlyAffectsWarmupCount(t *testing.T) {
	e := NewEvaluator(Config{WarmupEvents: 2})

	// crypto/fs events have no "host" field to record, but should still
	// count toward warmup -- ObserveOnly must not silently skip them.
	e.ObserveOnly("dev:app", "crypto", json.RawMessage(`{"transformation":"AES/GCM/NoPadding"}`), "")
	e.ObserveOnly("dev:app", "fs", json.RawMessage(`{"path":"/tmp/cache.db"}`), "")
	e.ObserveOnly("dev:app", "network", json.RawMessage(`{"host":"api.example.com"}`), "")

	// 4th event, count=4 > warmupEvents=2 -> warmed up, genuinely new host.
	m := e.Evaluate("dev:app", "network", json.RawMessage(`{"host":"new.example.com"}`), nil)
	if !contains(m, "first_seen_host") {
		t.Fatalf("expected warmup to be cleared by the 3 ObserveOnly calls (any kind) plus this event, got %v", m)
	}
}

func TestCheckVersionChange_FirstEventNeverReportsChanged(t *testing.T) {
	e := NewEvaluator(Config{})
	changed, previous := e.CheckVersionChange("dev:app", "1.0.0:100")
	if changed {
		t.Fatalf("first-ever version for a source should not report changed (nothing to compare against), got changed=%v previous=%q", changed, previous)
	}
}

func TestCheckVersionChange_DetectsRealChange(t *testing.T) {
	e := NewEvaluator(Config{})
	e.CheckVersionChange("dev:app", "1.0.0:100")

	changed, previous := e.CheckVersionChange("dev:app", "1.1.0:101")
	if !changed {
		t.Fatal("expected a version change to be detected")
	}
	if previous != "1.0.0:100" {
		t.Fatalf("expected previous version '1.0.0:100', got %q", previous)
	}
}

func TestCheckVersionChange_SameVersionRepeatedDoesNotReflag(t *testing.T) {
	e := NewEvaluator(Config{})
	e.CheckVersionChange("dev:app", "1.0.0:100")

	changed, _ := e.CheckVersionChange("dev:app", "1.0.0:100")
	if changed {
		t.Fatal("the same version repeated should not report a change")
	}
}

func TestCheckVersionChange_UnknownVersionIsIgnored(t *testing.T) {
	// agent/hooks.js sends "unknown" before it finishes resolving the
	// real version asynchronously -- that must never be treated as a
	// real version, or a slow resolution race could look like two
	// spurious "updates" (unknown -> real, in whichever order events
	// happen to arrive).
	e := NewEvaluator(Config{})
	e.CheckVersionChange("dev:app", "unknown")
	changed, previous := e.CheckVersionChange("dev:app", "1.0.0:100")
	if changed {
		t.Fatalf("transitioning from ignored 'unknown' to a real version should not itself count as a change, got previous=%q", previous)
	}
}

func TestCheckVersionChange_IsolatedPerSource(t *testing.T) {
	e := NewEvaluator(Config{})
	e.CheckVersionChange("dev:appA", "1.0.0:100")
	// A completely different source's first version must not be
	// compared against appA's -- same isolation guarantee as seenHosts
	// and eventCounts.
	changed, _ := e.CheckVersionChange("dev:appB", "5.0.0:500")
	if changed {
		t.Fatal("source B's first version should not be compared against source A's version history")
	}
}

func TestObserveOnly_RebuildsVersionStateFromHistory(t *testing.T) {
	e := NewEvaluator(Config{})

	// Simulate replaying history ending at version 1.2.0.
	e.ObserveOnly("dev:app", "network", json.RawMessage(`{"host":"a.example.com"}`), "1.0.0:100")
	e.ObserveOnly("dev:app", "network", json.RawMessage(`{"host":"b.example.com"}`), "1.2.0:120")

	// Post-replay, a live event still on 1.2.0 should NOT report a
	// change -- if ObserveOnly didn't rebuild version state, this would
	// incorrectly look like a fresh "unknown -> 1.2.0" transition.
	changed, _ := e.CheckVersionChange("dev:app", "1.2.0:120")
	if changed {
		t.Fatal("version already established via ObserveOnly replay should not re-flag as changed for the same version live")
	}

	// A genuinely newer version post-replay SHOULD report change, with
	// the correct previous version from history.
	changed, previous := e.CheckVersionChange("dev:app", "1.3.0:130")
	if !changed || previous != "1.2.0:120" {
		t.Fatalf("expected change from the replayed version 1.2.0:120, got changed=%v previous=%q", changed, previous)
	}
}

// TestEvaluate_RSAOAEPIsNotFlaggedAsWeakCipher is a regression test for a
// real false positive found during live end-to-end testing of an
// unrelated feature (the compressor-disagreement scorer), not a
// hypothetical. RSA/ECB/OAEPWithSHA-256AndMGF1Padding -- a modern,
// RECOMMENDED RSA configuration -- was matching the generic "/ecb/"
// weak-cipher-mode pattern purely on substring coincidence: Java's
// transformation-string convention uses "ECB" as an RSA padding-scheme
// placeholder, not a genuine block-cipher mode indicator the way it is
// for AES/DES.
func TestEvaluate_RSAOAEPIsNotFlaggedAsWeakCipher(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if contains(matches, "weak_cipher") {
		t.Fatalf("RSA-OAEP is a modern, recommended configuration and should not match weak_cipher, got %v", matches)
	}
}

func TestEvaluate_RSAWithLegacyPKCS1PaddingIsStillFlagged(t *testing.T) {
	// The fix for the false positive above must not throw out the real
	// signal: legacy PKCS1v1.5 padding for RSA (vulnerable to
	// Bleichenbacher-style padding-oracle attacks) is a genuine weakness,
	// distinct from the ECB-placeholder naming quirk, and must still be
	// caught -- via the "pkcs1padding" pattern, not the excluded ECB one.
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"RSA/ECB/PKCS1Padding"}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if !contains(matches, "weak_cipher") {
		t.Fatalf("RSA with legacy PKCS1v1.5 padding is a genuine weakness and should still be flagged, got %v", matches)
	}
}

func TestEvaluate_NonRSAECBIsStillFlaggedNormally(t *testing.T) {
	// The RSA-specific exclusion must not weaken detection for the
	// symmetric block ciphers the ECB pattern actually exists to catch.
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"AES/ECB/NoPadding"}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if !contains(matches, "weak_cipher") {
		t.Fatalf("AES/ECB is a genuine weak-mode finding and must still be flagged, got %v", matches)
	}
}

func TestEvaluate_SecretLeakDetectedOnNetworkEvent(t *testing.T) {
	// Simulates agent/hooks.js's header-scan finding a leaked token in a
	// request header -- the ACTUAL value never reaches this code, only
	// the redacted pattern name (see agent/hooks.js's scanForSecrets doc).
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"host":"api.example.com","secret_pattern":"aws_access_key","secret_preview":"AKIA...(20 chars)","secret_location":"header"}`)
	matches := e.Evaluate("dev:app", "network", detail, nil)
	if !contains(matches, "secret_leak:aws_access_key") {
		t.Fatalf("expected secret_leak:aws_access_key, got %v", matches)
	}
}

func TestEvaluate_SecretLeakDetectedOnFsEvent(t *testing.T) {
	// Simulates the SharedPreferences value scan.
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"shared_prefs_write","key":"api_token","secret_pattern":"stripe_live_key","secret_location":"shared_prefs:api_token"}`)
	matches := e.Evaluate("dev:app", "fs", detail, nil)
	if !contains(matches, "secret_leak:stripe_live_key") {
		t.Fatalf("expected secret_leak:stripe_live_key, got %v", matches)
	}
}

func TestEvaluate_SecretLeakDetectedOnCustomEvent(t *testing.T) {
	// Simulates the Log.d/e/w/i/v scan.
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"log_secret","level":"d","tag":"AuthManager","secret_pattern":"jwt","secret_location":"log:d"}`)
	matches := e.Evaluate("dev:app", "custom", detail, nil)
	if !contains(matches, "secret_leak:jwt") {
		t.Fatalf("expected secret_leak:jwt, got %v", matches)
	}
}

func TestEvaluate_NoSecretPatternFieldMeansNoLeak(t *testing.T) {
	// Ordinary events (the overwhelming majority) have no secret_pattern
	// field at all -- must not spuriously flag.
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"host":"api.example.com","path":"/v1/sync"}`)
	matches := e.Evaluate("dev:app", "network", detail, nil)
	for _, m := range matches {
		if strings.HasPrefix(m, "secret_leak") {
			t.Fatalf("expected no secret_leak match without a secret_pattern field, got %v", matches)
		}
	}
}

func TestEvaluate_SecretLeakCanCoexistWithOtherRules(t *testing.T) {
	// A weak cipher AND a leaked key in the same event (e.g. a hardcoded
	// key used to configure a broken cipher) should surface both --
	// secret_leak doesn't suppress or get suppressed by kind-specific
	// rules.
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"DES/ECB/NoPadding","secret_pattern":"high_entropy_string"}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if !contains(matches, "weak_cipher") || !contains(matches, "secret_leak:high_entropy_string") {
		t.Fatalf("expected BOTH weak_cipher and secret_leak to fire together, got %v", matches)
	}
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

// ---- Intent / Deep Link tests ----

func TestEvaluate_InsecureIntentFlagsImplicitWithSensitiveURI(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"start_activity","action":"android.intent.action.VIEW","data_uri":"myapp://login?token=abc123","is_explicit":false,"component":"","has_grant_uri_permission":false}`)
	matches := e.Evaluate("dev:app", "intent", detail, nil)
	if !contains(matches, "insecure_intent") {
		t.Fatalf("expected insecure_intent for implicit intent with token in URI, got %v", matches)
	}
}

func TestEvaluate_ExplicitIntentWithSensitiveURIIsSafe(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"start_activity","action":"android.intent.action.VIEW","data_uri":"myapp://login?token=abc123","is_explicit":true,"component":"com.example/.LoginActivity","has_grant_uri_permission":false}`)
	matches := e.Evaluate("dev:app", "intent", detail, nil)
	if contains(matches, "insecure_intent") {
		t.Fatalf("explicit intents should not trigger insecure_intent, got %v", matches)
	}
}

func TestEvaluate_ImplicitIntentWithURIGrantFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"send_broadcast","action":"com.example.SHARE","data_uri":"content://com.example/data","is_explicit":false,"component":"","has_grant_uri_permission":true}`)
	matches := e.Evaluate("dev:app", "intent", detail, nil)
	if !contains(matches, "insecure_intent") {
		t.Fatalf("implicit intent with URI grant should flag, got %v", matches)
	}
}

func TestEvaluate_ImplicitIntentWithInnocuousURIIsSafe(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"start_activity","action":"android.intent.action.VIEW","data_uri":"https://www.example.com/help","is_explicit":false,"component":"","has_grant_uri_permission":false}`)
	matches := e.Evaluate("dev:app", "intent", detail, nil)
	if contains(matches, "insecure_intent") {
		t.Fatalf("innocuous URI should not trigger insecure_intent, got %v", matches)
	}
}

func TestEvaluate_IntentScopedToIntentKindOnly(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"start_activity","data_uri":"myapp://auth?token=x","is_explicit":false}`)
	matches := e.Evaluate("dev:app", "network", detail, nil)
	if contains(matches, "insecure_intent") {
		t.Fatalf("insecure_intent should not fire on non-intent kinds, got %v", matches)
	}
}

// ---- SQL Injection tests ----

func TestEvaluate_SQLInjectionPatternInRawQuery(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"raw_query","query":"SELECT * FROM users WHERE name = '' OR '1'='1'","parameterized":false,"arg_count":0}`)
	matches := e.Evaluate("dev:app", "sql", detail, nil)
	if !contains(matches, "insecure_sql_query") {
		t.Fatalf("expected insecure_sql_query for OR injection pattern, got %v", matches)
	}
}

func TestEvaluate_ParameterizedQueryIsSafe(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"raw_query","query":"SELECT * FROM users WHERE id = ?","parameterized":true,"arg_count":1}`)
	matches := e.Evaluate("dev:app", "sql", detail, nil)
	if contains(matches, "insecure_sql_query") {
		t.Fatalf("parameterized query should not trigger insecure_sql_query, got %v", matches)
	}
}

func TestEvaluate_ExecSQLWithWhereClauseFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"exec_sql","query":"DELETE FROM sessions WHERE user_id = 42","parameterized":false}`)
	matches := e.Evaluate("dev:app", "sql", detail, nil)
	if !contains(matches, "insecure_sql_query") {
		t.Fatalf("execSQL with WHERE clause should flag, got %v", matches)
	}
}

func TestEvaluate_ExecSQLCreateTableIsSafe(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"exec_sql","query":"CREATE TABLE IF NOT EXISTS cache (id INTEGER PRIMARY KEY)","parameterized":false}`)
	matches := e.Evaluate("dev:app", "sql", detail, nil)
	if contains(matches, "insecure_sql_query") {
		t.Fatalf("CREATE TABLE should not trigger insecure_sql_query, got %v", matches)
	}
}

func TestEvaluate_RawQueryWithWhereNoPlaceholders(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"raw_query","query":"SELECT * FROM accounts WHERE email = 'admin@test.com'","parameterized":false,"arg_count":0}`)
	matches := e.Evaluate("dev:app", "sql", detail, nil)
	if !contains(matches, "insecure_sql_query") {
		t.Fatalf("rawQuery with WHERE but no ? should flag, got %v", matches)
	}
}

func TestEvaluate_SQLScopedToSQLKindOnly(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"raw_query","query":"SELECT * FROM users WHERE 1=1","parameterized":false}`)
	matches := e.Evaluate("dev:app", "network", detail, nil)
	if contains(matches, "insecure_sql_query") {
		t.Fatalf("insecure_sql_query should not fire on non-sql kinds, got %v", matches)
	}
}

// ---- WebView tests ----

func TestEvaluate_WebViewJSInterfaceFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"js_interface","setting":"addJavascriptInterface","interface_name":"AndroidBridge"}`)
	matches := e.Evaluate("dev:app", "webview", detail, nil)
	if !contains(matches, "insecure_webview") {
		t.Fatalf("addJavascriptInterface should flag insecure_webview, got %v", matches)
	}
}

func TestEvaluate_WebViewMixedContentAlwaysAllowFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"mixed_content","setting":"setMixedContentMode","value":0}`)
	matches := e.Evaluate("dev:app", "webview", detail, nil)
	if !contains(matches, "insecure_webview") {
		t.Fatalf("MIXED_CONTENT_ALWAYS_ALLOW should flag, got %v", matches)
	}
}

func TestEvaluate_WebViewMixedContentNeverAllowIsSafe(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"mixed_content","setting":"setMixedContentMode","value":1}`)
	matches := e.Evaluate("dev:app", "webview", detail, nil)
	if contains(matches, "insecure_webview") {
		t.Fatalf("MIXED_CONTENT_NEVER_ALLOW should not flag, got %v", matches)
	}
}

func TestEvaluate_WebViewFileAccessFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"file_access","setting":"setAllowFileAccess","value":true}`)
	matches := e.Evaluate("dev:app", "webview", detail, nil)
	if !contains(matches, "insecure_webview") {
		t.Fatalf("file access should flag insecure_webview, got %v", matches)
	}
}

func TestEvaluate_WebViewJSEnabledAloneDoesNotFlag(t *testing.T) {
	// JavaScript enabled alone is too common to flag -- it's the
	// combination with file access or JS interfaces that's dangerous.
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"js_enabled","setting":"setJavaScriptEnabled","value":true}`)
	matches := e.Evaluate("dev:app", "webview", detail, nil)
	if contains(matches, "insecure_webview") {
		t.Fatalf("JS enabled alone should not flag, got %v", matches)
	}
}

func TestEvaluate_WebViewScopedToWebviewKindOnly(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"js_interface","setting":"addJavascriptInterface","interface_name":"Bridge"}`)
	matches := e.Evaluate("dev:app", "custom", detail, nil)
	if contains(matches, "insecure_webview") {
		t.Fatalf("insecure_webview should not fire on non-webview kinds, got %v", matches)
	}
}

// ---- Biometric tests ----

func TestEvaluate_BiometricWithoutCryptoObjectFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"authenticate","api":"BiometricPrompt","has_crypto_object":false}`)
	matches := e.Evaluate("dev:app", "biometric", detail, nil)
	if !contains(matches, "weak_biometric") {
		t.Fatalf("authenticate without CryptoObject should flag weak_biometric, got %v", matches)
	}
}

func TestEvaluate_BiometricWithCryptoObjectIsSafe(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"authenticate","api":"BiometricPrompt","has_crypto_object":true}`)
	matches := e.Evaluate("dev:app", "biometric", detail, nil)
	if contains(matches, "weak_biometric") {
		t.Fatalf("authenticate with CryptoObject should not flag, got %v", matches)
	}
}

func TestEvaluate_BiometricScopedToBiometricKindOnly(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"authenticate","api":"BiometricPrompt","has_crypto_object":false}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if contains(matches, "weak_biometric") {
		t.Fatalf("weak_biometric should not fire on non-biometric kinds, got %v", matches)
	}
}

func TestEvaluate_AndroidXBiometricWithoutCryptoFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"authenticate","api":"androidx.BiometricPrompt","has_crypto_object":false}`)
	matches := e.Evaluate("dev:app", "biometric", detail, nil)
	if !contains(matches, "weak_biometric") {
		t.Fatalf("AndroidX BiometricPrompt without crypto should flag, got %v", matches)
	}
}

// ---- Native tests ----

func TestEvaluate_NativeDexLoadFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"dex_load","size":12345}`)
	matches := e.Evaluate("dev:app", "native", detail, nil)
	if !contains(matches, "dynamic_dex_load") {
		t.Fatalf("dex_load should flag dynamic_dex_load, got %v", matches)
	}
}

func TestEvaluate_NativeJNIRegistrationFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"jni_registration","method":"test","address":"0x123"}`)
	matches := e.Evaluate("dev:app", "native", detail, nil)
	if !contains(matches, "dynamic_jni_registration") {
		t.Fatalf("jni_registration should flag dynamic_jni_registration, got %v", matches)
	}
}

func TestEvaluate_NativeTLSSecretLeakFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"ssl_write","bytes":"100","secret_pattern":"sk_live_","secret_preview":"sk_live_123..."}`)
	matches := e.Evaluate("dev:app", "native_tls", detail, nil)
	if !contains(matches, "native_tls_secret_leak:sk_live_") {
		t.Fatalf("ssl_write with secret should flag native_tls_secret_leak, got %v", matches)
	}
}
