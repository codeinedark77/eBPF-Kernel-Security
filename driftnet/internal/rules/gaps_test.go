package rules

import (
	"encoding/json"
	"testing"
)

// ---- Gap tests ----

func TestEvaluate_InsecureBroadcastReceiverFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"register_receiver","receiver_class":"com.evil.Receiver","permission":"none"}`)
	matches := e.Evaluate("dev:app", "ipc", detail, nil)
	if !contains(matches, "insecure_broadcast_receiver") {
		t.Fatalf("register_receiver with none permission should flag insecure_broadcast_receiver, got %v", matches)
	}
}

func TestEvaluate_SecureBroadcastReceiverNotFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"register_receiver","receiver_class":"com.evil.Receiver","permission":"com.example.permission.CUSTOM"}`)
	matches := e.Evaluate("dev:app", "ipc", detail, nil)
	if contains(matches, "insecure_broadcast_receiver") {
		t.Fatalf("register_receiver with permission should not flag, got %v", matches)
	}
}

func TestEvaluate_TapjackingRiskFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"activity_resume","activity":"com.evil.Activity","filter_touches":false}`)
	matches := e.Evaluate("dev:app", "ui", detail, nil)
	if !contains(matches, "tapjacking_risk") {
		t.Fatalf("activity_resume with filter_touches=false should flag tapjacking_risk, got %v", matches)
	}
}

func TestEvaluate_TapjackingSafeNotFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"activity_resume","activity":"com.evil.Activity","filter_touches":true}`)
	matches := e.Evaluate("dev:app", "ui", detail, nil)
	if contains(matches, "tapjacking_risk") {
		t.Fatalf("activity_resume with filter_touches=true should not flag, got %v", matches)
	}
}

func TestEvaluate_WeakHostnameVerificationFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"set_hostname_verifier","verifier_class":"com.evil.CustomVerifier","is_default_or_safe":false}`)
	matches := e.Evaluate("dev:app", "network", detail, nil)
	if !contains(matches, "weak_hostname_verification") {
		t.Fatalf("set_hostname_verifier with unsafe verifier should flag weak_hostname_verification, got %v", matches)
	}
}

func TestEvaluate_DefaultHostnameVerificationNotFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"set_hostname_verifier","verifier_class":"okhttp3.internal.tls.OkHostnameVerifier","is_default_or_safe":true}`)
	matches := e.Evaluate("dev:app", "network", detail, nil)
	if contains(matches, "weak_hostname_verification") {
		t.Fatalf("set_hostname_verifier with safe verifier should not flag, got %v", matches)
	}
}

func TestEvaluate_AntiAnalysisFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"file_exists","target":"/system/xbin/su"}`)
	matches := e.Evaluate("dev:app", "anti_analysis", detail, nil)
	if !contains(matches, "anti_analysis_detected") {
		t.Fatalf("anti_analysis event should flag anti_analysis_detected, got %v", matches)
	}
}

func TestEvaluate_TracingFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"class_load","class_name":"com.stripe.android.PaymentSession"}`)
	matches := e.Evaluate("dev:app", "tracing", detail, nil)
	if !contains(matches, "high_value_class_loaded") {
		t.Fatalf("tracing event should flag high_value_class_loaded, got %v", matches)
	}
}

func TestEvaluate_BinderFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"transact","code":1,"interface":"android.content.IIntentSender"}`)
	matches := e.Evaluate("dev:app", "binder", detail, nil)
	if !contains(matches, "binder_transaction:1") {
		t.Fatalf("binder event should flag binder_transaction:1, got %v", matches)
	}
}

func TestEvaluate_DCLFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"dex_class_loader","path":"/sdcard/Download/payload.dex"}`)
	matches := e.Evaluate("dev:app", "dcl", detail, nil)
	if !contains(matches, "insecure_dcl") {
		t.Fatalf("dcl event on external storage should flag insecure_dcl, got %v", matches)
	}
}

func TestEvaluate_WeakCryptoModesFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"api":"Cipher.getInstance","transformation":"AES/ECB/PKCS5Padding"}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if !contains(matches, "weak_cipher") {
		t.Fatalf("crypto event with ECB mode should flag weak_cipher, got %v", matches)
	}
}

func TestEvaluate_SharedPreferencesSecretsFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"shared_prefs_write","key":"api_key","secret_pattern":"high_entropy_string"}`)
	matches := e.Evaluate("dev:app", "fs", detail, nil)
	if !contains(matches, "secret_leak:high_entropy_string") {
		t.Fatalf("fs event with secret_pattern should flag secret_leak, got %v", matches)
	}
}

func TestEvaluate_ZipSlipFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"zip_entry_get_name","path":"../../../../data/data/com.app/shared_prefs/prefs.xml"}`)
	matches := e.Evaluate("dev:app", "fs", detail, nil)
	if !contains(matches, "insecure_zip_traversal") {
		t.Fatalf("fs event with zip slip path should flag insecure_zip_traversal, got %v", matches)
	}
}

func TestEvaluate_PendingIntentFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"pending_intent_getActivity","is_mutable":true,"is_implicit":true}`)
	matches := e.Evaluate("dev:app", "intent", detail, nil)
	if !contains(matches, "insecure_pending_intent") {
		t.Fatalf("intent event with mutable and implicit pending intent should flag insecure_pending_intent, got %v", matches)
	}
}

func TestEvaluate_JniRegisterNativesFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"register_natives","method_name":"stringFromJNI","signature":"()Ljava/lang/String;","fn_ptr":"0x7d6a543b2a"}`)
	matches := e.Evaluate("dev:app", "jni", detail, nil)
	if !contains(matches, "jni_binding:stringFromJNI") {
		t.Fatalf("jni event should flag jni_binding, got %v", matches)
	}
}

func TestEvaluate_SecureRandomSeedFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"api":"SecureRandom.setSeed","seed_length":8}`)
	matches := e.Evaluate("dev:app", "crypto", detail, nil)
	if !contains(matches, "insecure_random_seed") {
		t.Fatalf("crypto event for SecureRandom.setSeed should flag insecure_random_seed, got %v", matches)
	}
}

func TestEvaluate_FlagSecureFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"sensitive_activity_resume","activity_name":"com.example.LoginActivity","has_flag_secure":false}`)
	matches := e.Evaluate("dev:app", "ui", detail, nil)
	if !contains(matches, "missing_flag_secure") {
		t.Fatalf("ui event with missing flag secure should flag missing_flag_secure, got %v", matches)
	}
}

func TestEvaluate_InsecureFilePermissionsFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"open_file_output","name":"secrets.txt","mode":1}`)
	matches := e.Evaluate("dev:app", "fs", detail, nil)
	if !contains(matches, "insecure_file_permissions") {
		t.Fatalf("fs event with MODE_WORLD_READABLE (mode: 1) should flag insecure_file_permissions, got %v", matches)
	}
}

func TestEvaluate_SecureSettingsFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"secure_settings_query","setting":"adb_enabled"}`)
	matches := e.Evaluate("dev:app", "anti_analysis", detail, nil)
	if !contains(matches, "anti_analysis_detected") {
		t.Fatalf("anti_analysis event for secure settings query should flag anti_analysis_detected, got %v", matches)
	}
}

func TestEvaluate_MemoryScannerFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"memory_scan","secret_pattern":"AKIA_KEY_PATTERN","address":"0x7f23a1b4"}`)
	matches := e.Evaluate("dev:app", "memory", detail, nil)
	if !contains(matches, "memory_secret_leak:AKIA_KEY_PATTERN") {
		t.Fatalf("memory event with secret_pattern should flag memory_secret_leak, got %v", matches)
	}
}

func TestEvaluate_RawSyscallFlagged(t *testing.T) {
	e := NewEvaluator(Config{})
	detail := json.RawMessage(`{"op":"raw_syscall","address":"0x794b12cf"}`)
	matches := e.Evaluate("dev:app", "tracing", detail, nil)
	if !contains(matches, "raw_syscall_detected") {
		t.Fatalf("tracing event with raw_syscall should flag raw_syscall_detected, got %v", matches)
	}
}
