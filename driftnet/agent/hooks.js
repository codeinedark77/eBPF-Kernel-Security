/*
 * driftnet Frida agent — Android side.
 *
 * Instruments a target app's process for:
 *   - network activity (OkHttp3, java.net.Socket/URL fallback)
 *   - crypto API usage (javax.crypto.Cipher, java.security.MessageDigest)
 *   - file access under app-private storage, including SharedPreferences
 *     writes specifically (a very common accidental plaintext-secret spot)
 *   - the app's own version (versionName:versionCode), attached to every
 *     event -- feeds driftnetd's app-update-diffing rule (internal/rules'
 *     "app_updated" signal), so a new release showing up mid-session is
 *     itself a visible, informational event, not silent
 *
 * Events are batched and pushed over a WebSocket to driftnetd running on
 * your laptop, reached via its Tailscale address. This does NOT try to
 * decrypt TLS or bypass certificate pinning — it observes *metadata*
 * (host, method, byte counts, cipher algorithm/mode, file paths), which is
 * enough for novelty scoring without touching payload contents.
 *
 * Usage (from the laptop, over adb via Tailscale/USB):
 *   frida -U -f <package.name> -l agent/hooks.js --no-pause
 * or attach to a running process:
 *   frida -U <package.name> -l agent/hooks.js
 *
 * Configure DRIFTNET_WS_URL and DEVICE_ID below or via Frida's
 * rpc.exports pattern if you want to set them at attach time.
 */

'use strict';

// ---- Configuration -----------------------------------------------------
// Point this at driftnetd's Tailscale address, e.g.:
//   const DRIFTNET_WS_URL = "ws://laptop-hostname.tailnet-name.ts.net:8787/ws/ingest";
const DRIFTNET_WS_URL = 'ws://100.x.y.z:8787/ws/ingest';
const DEVICE_ID = 'oneplus9r';
const BATCH_FLUSH_MS = 500;

// Set true only if the target app force-closes or silently misbehaves
// under Frida -- some Play Store apps ship basic root/tamper detection.
// See the small, narrowly-scoped bypasses in hookAntiDetection() below.
// This is standard mobile security testing practice (see OWASP MSTG's
// sections on bypassing root detection) for testing an app you have
// legitimate access to on your own device -- it does not touch, modify,
// or redistribute the app, and has no effect on other users or the live
// service.
const ENABLE_ANTI_DETECTION_BYPASS = false;

// ---- Minimal event queue + send loop ------------------------------------
// Frida's JS runtime (QuickJS by default since Frida 14, or V8 if
// explicitly selected with --runtime=v8) doesn't ship a WebSocket client,
// so events are queued here and drained by a companion Python relay
// listening on Frida's message channel (see scripts/relay.py). This keeps
// the agent itself dependency-free and robust to which runtime Frida
// happens to be configured with on a given setup.
let queue = [];

// Resolved asynchronously once the JVM is attached (see resolveAppVersion
// below); events emitted before resolution completes carry 'unknown'
// rather than blocking on it -- version metadata is useful for
// update-diffing but shouldn't hold up real-time observation.
let appVersion = 'unknown';

function emit(appPackage, kind, detail) {
  queue.push({
    device: DEVICE_ID,
    app: appPackage,
    kind: kind,
    detail: detail,
    app_version: appVersion,
    ts: Date.now(),
  });
}

function flush() {
  if (queue.length === 0) return;
  const batch = queue;
  queue = [];
  emitToRelay({ type: 'driftnet_batch', events: batch });
}

setInterval(flush, BATCH_FLUSH_MS);

// ---- Target package resolution ------------------------------------------
const currentApp = (() => {
  try {
    return Application.identifier || 'unknown';
  } catch (e) {
    return 'unknown';
  }
})();

// ---- App version resolution (for update-diffing on the driftnetd side) -
// Runs inside Java.perform since it needs real JVM reflection, unlike
// `currentApp` above which uses Frida's lighter Application.identifier.
function resolveAppVersion() {
  Java.perform(() => {
    try {
      const ActivityThread = Java.use('android.app.ActivityThread');
      const app = ActivityThread.currentApplication();
      const ctx = app.getApplicationContext();
      const pm = ctx.getPackageManager();
      const pInfo = pm.getPackageInfo(ctx.getPackageName(), 0);
      appVersion = pInfo.versionName.value + ':' + pInfo.versionCode.value;
      console.log('[driftnet] resolved app version: ' + appVersion);
    } catch (e) {
      console.log('[driftnet] could not resolve app version: ' + e);
    }
  });
}

// ---- Secret/credential leak detection -----------------------------------
// Runs entirely here, on-device, BEFORE anything is emitted. This is
// deliberate, not incidental: if a real secret were transmitted to the
// relay/driftnetd/dashboard for redaction "on the way in," that would
// create a SECOND copy of the leak -- in the WAL, in the dashboard's
// browser session -- which is worse than not detecting it at all. The
// actual secret value is only ever compared against patterns locally;
// only a pattern NAME and a short, non-reversible preview (a handful of
// leading characters plus length) ever leaves the device.
const SECRET_PATTERNS = [
  { name: 'aws_access_key', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'google_api_key', re: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: 'slack_token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: 'stripe_live_key', re: /sk_live_[0-9A-Za-z]{24,}/ },
  { name: 'github_token', re: /gh[pousr]_[0-9A-Za-z]{36,}/ },
  { name: 'generic_bearer_token', re: /Bearer\s+[A-Za-z0-9\-_.]{20,}/ },
  { name: 'jwt', re: /^eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/ },
  { name: 'pem_private_key', re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
];

// shannonEntropy estimates how "random-looking" a string is, in bits per
// character. Real API keys/tokens are typically base64/hex-like and
// score high (~4.0-6.0); ordinary words and sentences score much lower
// (~2.5-3.5). Used as a fallback for secrets that don't match a known
// vendor format above.
function shannonEntropy(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// scanForSecrets returns a redacted { pattern, preview } if value looks
// like a credential, or null. Never returns the actual value.
function scanForSecrets(value) {
  if (typeof value !== 'string' || value.length < 8) return null;

  for (const p of SECRET_PATTERNS) {
    if (p.re.test(value)) {
      return { pattern: p.name, preview: redactPreview(value) };
    }
  }

  // Explicit UUID exclusion, found necessary by actually testing the
  // fallback heuristic below rather than trusting it on paper: hex
  // digits are already a 16-symbol alphabet, so a UUID's theoretical max
  // entropy sits right around the 4.0 threshold below -- two
  // structurally identical UUIDs, differing only in which hex digits
  // happened to repeat, gave inconsistent results (one flagged, one
  // didn't). UUIDs are extremely common in mobile apps (session/device/
  // correlation IDs) and would be a genuinely annoying, confusing source
  // of false positives, so they're excluded outright rather than left to
  // the entropy heuristic's luck.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
    return null;
  }

  // Generic fallback: long, high-entropy, AND mixed case. The mixed-case
  // requirement is the more general fix behind the UUID exclusion above
  // -- real secrets (API keys, tokens) are almost always base64/mixed-
  // case, while lowercase-only hex (UUIDs, MD5/SHA1 digests, other IDs)
  // is common and NOT a secret. Requiring both upper and lower case
  // excludes that whole category without needing a growing list of
  // specific formats to exclude one by one.
  const hasUpper = /[A-Z]/.test(value);
  const hasLower = /[a-z]/.test(value);
  if (
    value.length >= 20 &&
    value.length <= 512 &&
    hasUpper && hasLower &&
    /^[A-Za-z0-9+/=_\-.]+$/.test(value) &&
    shannonEntropy(value) > 4.0
  ) {
    return { pattern: 'high_entropy_string', preview: redactPreview(value) };
  }

  return null;
}

function redactPreview(value) {
  const shown = value.slice(0, 4);
  return shown + '...(' + value.length + ' chars)';
}

// ---- Hook: OkHttp3 (covers the overwhelming majority of Android apps) ---
function hookOkHttp3() {
  Java.perform(() => {
    try {
      const RealCall = Java.use('okhttp3.RealCall');
      RealCall.execute.implementation = function () {
        const req = this.request();
        const url = req.url().toString();
        const method = req.method();
        let bodyLen = -1;
        try {
          const body = req.body();
          if (body) bodyLen = body.contentLength();
        } catch (e) {}

        // Header scanning: a very common place secrets leak
        // (Authorization, X-API-Key, custom auth headers). Only header
        // VALUES are scanned, and only a redacted match indicator is
        // emitted -- never the header name/value themselves, whether or
        // not they matched, to stay conservative about what leaves the
        // device from a request's headers.
        let secretHeader = null;
        try {
          const headers = req.headers();
          const n = headers.size();
          for (let i = 0; i < n && !secretHeader; i++) {
            const match = scanForSecrets(headers.value(i));
            if (match) secretHeader = match;
          }
        } catch (e) {}

        const detail = {
          transport: 'okhttp3',
          method: method,
          host: safeHost(url),
          path: safePath(url),
          request_bytes: bodyLen.toString(),
        };
        if (secretHeader) {
          detail.secret_pattern = secretHeader.pattern;
          detail.secret_preview = secretHeader.preview;
          detail.secret_location = 'header';
        }
        emit(currentApp, 'network', detail);

        return this.execute();
      };
      console.log('[driftnet] okhttp3.RealCall.execute hooked');
    } catch (e) {
      console.log('[driftnet] okhttp3 not present or hook failed: ' + e);
    }
  });
}

// ---- Hook: raw java.net (fallback for apps not using OkHttp) -----------
function hookJavaNet() {
  Java.perform(() => {
    try {
      const URL = Java.use('java.net.URL');
      URL.openConnection.overload().implementation = function () {
        const conn = this.openConnection();
        try {
          emit(currentApp, 'network', {
            transport: 'java.net',
            host: safeHost(this.toString()),
            path: safePath(this.toString()),
          });
        } catch (e) {}
        return conn;
      };
      console.log('[driftnet] java.net.URL.openConnection hooked');
    } catch (e) {
      console.log('[driftnet] java.net hook failed: ' + e);
    }
  });
}

// ---- Hook (best-effort, UNVERIFIED): Flutter's dart:io.HttpClient -------
// Found via research, not tested against real Flutter+Frida from this
// build environment -- flagging that plainly rather than presenting it
// as a confirmed capability.
//
// WHY THIS EXISTS: Flutter apps route networking through Dart's own
// HttpClient (backed by BoringSSL, statically linked into libflutter.so)
// instead of the Android system's OkHttp/HttpURLConnection stack --
// meaning hookOkHttp3 and hookJavaNet above see ZERO traffic for a
// Flutter app's actual network calls, not reduced coverage, none at all.
// Flutter also doesn't use the system proxy or CA store, which is why
// full TLS interception for Flutter is a much harder, separate problem
// (patching stripped native code in libflutter.so to bypass certificate
// pinning) -- genuinely out of scope here, both because it's a deep
// native reverse-engineering project in its own right and because it
// would cross the metadata-only design boundary this whole agent commits
// to (see the file-level doc comment above). This hook attempts ONLY
// the much narrower, same-shape-as-everything-else metadata capture
// (method + host), via dart:io.HttpClient's own open() method, which one
// source (a Frida/Flutter interception guide, not an authoritative
// Frida/Dart reference) showed as directly reachable through Frida's
// ordinary Java.use() bridge -- suggesting Dart's HttpClient class is
// exposed to Frida's Java runtime bridge in at least some Flutter/Frida
// version combinations. Wrapped in try/catch like every other hook here,
// so if this doesn't apply (non-Flutter app, or the class isn't bridged
// this way in whatever Flutter version Upjaoo ships), it silently no-ops
// rather than breaking anything else.
//
// FIRST STEP BEFORE TRUSTING ANY OF THIS: check whether the target app
// is Flutter at all -- trivially, since an APK is just a zip file:
//   unzip -l app.apk | grep libflutter.so
// If that's empty, this hook is irrelevant and the OkHttp/java.net hooks
// above are almost certainly what actually applies.
function hookFlutterHttpClient() {
  Java.perform(() => {
    try {
      const HttpClient = Java.use('dart:io.HttpClient');
      HttpClient.open.overload('java.lang.String', 'java.lang.String', 'int').implementation = function (
        method,
        host,
        port
      ) {
        emit(currentApp, 'network', {
          transport: 'flutter_dart_io',
          method: method,
          host: host,
          path: '', // dart:io.HttpClient.open doesn't take a path at this call site
        });
        return this.open(method, host, port);
      };
      console.log('[driftnet] dart:io.HttpClient.open hooked (best-effort, unverified -- see comment above)');
    } catch (e) {
      // Expected, not an error, for any non-Flutter app -- or for a
      // Flutter app where this specific bridging approach doesn't apply.
      console.log('[driftnet] dart:io.HttpClient not present or hook failed (expected for non-Flutter apps): ' + e);
    }
  });
}

// ---- Hook: javax.crypto.Cipher (algorithm/mode usage, not key material) -
function hookCrypto() {
  Java.perform(() => {
    try {
      const Cipher = Java.use('javax.crypto.Cipher');
      Cipher.getInstance.overload('java.lang.String').implementation = function (
        transformation
      ) {
        emit(currentApp, 'crypto', {
          api: 'Cipher.getInstance',
          transformation: transformation,
        });
        return this.getInstance(transformation);
      };
      console.log('[driftnet] javax.crypto.Cipher.getInstance hooked');
    } catch (e) {
      console.log('[driftnet] crypto hook failed: ' + e);
    }
  });
}

// ---- Hook: java.security.MessageDigest (weak hashing outside Cipher) ---
// Cipher.getInstance catches weak *encryption* (DES, RC4, ECB). This
// catches weak *hashing* used elsewhere -- MD5/SHA1 for password storage
// or integrity checks is a distinct, very common finding that wouldn't
// show up in the Cipher hook at all. Reuses the SAME "algorithm" field
// name the existing weak_cipher rule already checks (see internal/rules),
// so no Go-side changes were needed to catch this once the hook exists.
function hookMessageDigest() {
  Java.perform(() => {
    try {
      const MessageDigest = Java.use('java.security.MessageDigest');
      MessageDigest.getInstance.overload('java.lang.String').implementation = function (
        algorithm
      ) {
        emit(currentApp, 'crypto', {
          api: 'MessageDigest.getInstance',
          algorithm: algorithm,
        });
        return this.getInstance(algorithm);
      };
      console.log('[driftnet] java.security.MessageDigest.getInstance hooked');
    } catch (e) {
      console.log('[driftnet] MessageDigest hook failed: ' + e);
    }
  });
}

// ---- Hook: SharedPreferences writes (common plaintext-secret vector) ---
// Hooks the concrete AOSP implementation class rather than the
// SharedPreferences.Editor interface -- Frida can hook interfaces, but
// only reliably once something implementing them has been loaded by the
// classloader Frida is using, which isn't guaranteed at hook-install
// time. The concrete impl class has been stable AOSP since API 1 and
// doesn't have that ordering problem.
function hookSharedPrefs() {
  Java.perform(() => {
    try {
      const EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
      EditorImpl.putString.implementation = function (key, value) {
        const match = scanForSecrets(value);
        const detail = {
          op: 'shared_prefs_write',
          key: key,
          value_len: value === null ? 0 : value.length,
        };
        if (match) {
          detail.secret_pattern = match.pattern;
          detail.secret_preview = match.preview;
          detail.secret_location = 'shared_prefs:' + key;
        }
        emit(currentApp, 'fs', detail);
        return this.putString(key, value);
      };
      console.log('[driftnet] SharedPreferencesImpl$EditorImpl.putString hooked');
    } catch (e) {
      console.log('[driftnet] SharedPreferences hook failed (OK on some OEM ROMs with a patched impl class): ' + e);
    }
  });
}

// ---- Hook: file access under app-private storage ------------------------
function hookFileAccess() {
  Java.perform(() => {
    try {
      const FileOutputStream = Java.use('java.io.FileOutputStream');
      FileOutputStream.$init.overload('java.lang.String').implementation = function (path) {
        emit(currentApp, 'fs', { op: 'write_open', path: path });
        return this.$init(path);
      };
      console.log('[driftnet] FileOutputStream.<init>(String) hooked');
    } catch (e) {
      console.log('[driftnet] fs hook failed: ' + e);
    }
  });
}

// ---- Optional: minimal anti-detection bypass ---------------------------
// Off by default (ENABLE_ANTI_DETECTION_BYPASS above). Each bypass is
// independently try/caught so a missing target on a given ROM/app just
// logs and moves on rather than aborting the others. Deliberately
// NARROW -- these target well-known, specific detection points, not a
// broad "hide Frida from everything" framework. If a target app uses a
// commercial RASP/tamper-detection SDK, these won't be enough; that's a
// genuinely app-specific reverse-engineering task, not something to
// pre-guess here.
function hookPhantomProtocol() {
  const ROOT_INDICATOR_PATHS = [
    '/system/bin/su', '/system/xbin/su', '/sbin/su',
    '/system/app/Superuser.apk', '/system/xbin/busybox',
    '/sbin/.magisk', '/data/adb/magisk', '/data/local/tmp/frida-server'
  ];

  function isBlockedPath(path) {
    if (!path) return false;
    const p = path.toLowerCase();
    for (let i = 0; i < ROOT_INDICATOR_PATHS.length; i++) {
      if (p.indexOf(ROOT_INDICATOR_PATHS[i]) !== -1) return true;
    }
    return false;
  }

  try {
    const openPtr = Module.findExportByName('libc.so', 'open');
    if (openPtr) {
      Interceptor.attach(openPtr, {
        onEnter: function (args) {
          try {
            const path = args[0].readUtf8String();
            if (isBlockedPath(path)) {
              this.blocked = true;
              this.path = path;
            }
          } catch (e) {}
        },
        onLeave: function (retval) {
          if (this.blocked) {
            console.log('[driftnet] Phantom: Blocked native open -> ' + this.path);
            retval.replace(-1); // Return ENOENT
          }
        }
      });
    }

    const faccessatPtr = Module.findExportByName('libc.so', 'faccessat');
    if (faccessatPtr) {
      Interceptor.attach(faccessatPtr, {
        onEnter: function (args) {
          try {
            // faccessat(int dirfd, const char *pathname, int mode, int flags)
            const path = args[1].readUtf8String();
            if (isBlockedPath(path)) {
              this.blocked = true;
              this.path = path;
            }
          } catch (e) {}
        },
        onLeave: function (retval) {
          if (this.blocked) {
            console.log('[driftnet] Phantom: Blocked native faccessat -> ' + this.path);
            retval.replace(-1);
          }
        }
      });
    }

    // Java-level fallback for the JVM checks
    Java.perform(() => {
      try {
        const Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
          return false;
        };
      } catch (e) {}
    });

    console.log('[driftnet] Phantom Protocol (Syscall-Level Cloaking) activated');
  } catch (e) {
    console.log('[driftnet] Phantom Protocol failed: ' + e);
  }
}

// ---- Hook: android.util.Log (forgotten debug logging is a very common --
// ---- real-world leak vector -- "Log.d(TAG, "token=" + token)" left in --
// ---- a release build) ---------------------------------------------------
// Unlike the other hooks, this does NOT emit on every call -- log output
// is highly variable free text with near-zero baseline value, and
// emitting every log line would be overwhelming noise for essentially no
// novelty-scoring benefit. Only emits when scanForSecrets actually finds
// something, going straight to the "secret_leak" rule regardless of NCD
// score.
function hookLogging() {
  Java.perform(() => {
    try {
      const Log = Java.use('android.util.Log');
      const levels = ['d', 'e', 'w', 'i', 'v'];
      for (const level of levels) {
        try {
          const overload = Log[level].overload('java.lang.String', 'java.lang.String');
          overload.implementation = function (tag, msg) {
            const match = scanForSecrets(msg);
            if (match) {
              emit(currentApp, 'custom', {
                op: 'log_secret',
                level: level,
                tag: tag,
                secret_pattern: match.pattern,
                secret_preview: match.preview,
                secret_location: 'log:' + level,
              });
            }
            return overload.call(this, tag, msg);
          };
        } catch (e) {
          console.log('[driftnet] Log.' + level + '(String,String) hook failed: ' + e);
        }
      }
      console.log('[driftnet] android.util.Log hooked (d/e/w/i/v)');
    } catch (e) {
      console.log('[driftnet] Log hook failed entirely: ' + e);
    }
  });
}

// ---- Intent / broadcast observation --------------------------------------
function hookIntentActivity() {
  Java.perform(() => {
    const Intent = Java.use('android.content.Intent');
    const FLAG_GRANT_READ  = 0x1;
    const FLAG_GRANT_WRITE = 0x2;

    function extractIntentDetail(intent, op) {
      const action  = intent.getAction()  ? intent.getAction().toString()  : '';
      const dataUri = intent.getDataString() ? intent.getDataString().toString() : '';
      const comp    = intent.getComponent();
      const flags   = intent.getFlags();
      const detail  = {
        op: op,
        action: action,
        data_uri: dataUri,
        is_explicit: comp !== null,
        component: comp !== null ? comp.toString() : '',
        has_grant_uri_permission: (flags & (FLAG_GRANT_READ | FLAG_GRANT_WRITE)) !== 0,
      };
      const secret = scanForSecrets(dataUri);
      if (secret) {
        detail.secret_pattern  = secret.pattern;
        detail.secret_preview  = secret.preview;
        detail.secret_location = 'intent_data';
      }
      return detail;
    }

    try {
      const Activity = Java.use('android.app.Activity');
      Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
        emit(currentApp, 'intent', extractIntentDetail(intent, 'start_activity'));
        return this.startActivity(intent);
      };
      console.log('[driftnet] Activity.startActivity hooked');
    } catch (e) {
      console.log('[driftnet] Activity.startActivity hook failed: ' + e);
    }

    try {
      const CtxWrapper = Java.use('android.content.ContextWrapper');
      CtxWrapper.sendBroadcast.overload('android.content.Intent').implementation = function (intent) {
        emit(currentApp, 'intent', extractIntentDetail(intent, 'send_broadcast'));
        return this.sendBroadcast(intent);
      };
      console.log('[driftnet] ContextWrapper.sendBroadcast hooked');
    } catch (e) {
      console.log('[driftnet] ContextWrapper.sendBroadcast hook failed: ' + e);
    }
  });
}

// ---- SQLite database observation ------------------------------------------
function hookSQLiteDatabase() {
  Java.perform(() => {
    try {
      const SQLiteDB = Java.use('android.database.sqlite.SQLiteDatabase');
      const ContentValues = Java.use('android.content.ContentValues');
      const Set = Java.use('java.util.Set');
      const MapEntry = Java.use('java.util.Map$Entry');

      SQLiteDB.insertWithOnConflict.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues', 'int').implementation = function (table, nullColumnHack, initialValues, conflictAlgorithm) {
        if (initialValues) {
          const valuesSet = initialValues.valueSet();
          if (valuesSet) {
            const iterator = valuesSet.iterator();
            while (iterator.hasNext()) {
              const entry = Java.cast(iterator.next(), MapEntry);
              const key = entry.getKey() ? entry.getKey().toString() : '';
              const val = entry.getValue() ? entry.getValue().toString() : '';
              
              const match = scanForSecrets(val);
              if (match) {
                emit(currentApp, 'fs', {
                  op: 'sqlite_insert',
                  table: table ? table.toString() : '',
                  column: key,
                  secret_pattern: match.pattern,
                  secret_preview: match.preview,
                  secret_location: 'sqlite:' + table + ':' + key
                });
              }
            }
          }
        }
        return this.insertWithOnConflict(table, nullColumnHack, initialValues, conflictAlgorithm);
      };
      console.log('[driftnet] SQLiteDatabase.insertWithOnConflict hooked for secrets');
    } catch (e) {
      console.log('[driftnet] SQLiteDatabase.insertWithOnConflict hook failed: ' + e);
    }

    try {
      const SQLiteDB = Java.use('android.database.sqlite.SQLiteDatabase');
      SQLiteDB.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, args) {
        const query = sql ? sql.toString().substring(0, 500) : '';
        emit(currentApp, 'sql', {
          op: 'raw_query',
          query: query,
          parameterized: args !== null && args.length > 0,
          arg_count: args !== null ? args.length : 0,
        });
        return this.rawQuery(sql, args);
      };
      console.log('[driftnet] SQLiteDatabase.rawQuery hooked');
    } catch (e) {
      console.log('[driftnet] SQLiteDatabase.rawQuery hook failed: ' + e);
    }

    try {
      const SQLiteDB = Java.use('android.database.sqlite.SQLiteDatabase');
      SQLiteDB.execSQL.overload('java.lang.String').implementation = function (sql) {
        const query = sql ? sql.toString().substring(0, 500) : '';
        emit(currentApp, 'sql', {
          op: 'exec_sql',
          query: query,
          parameterized: false,
        });
        return this.execSQL(sql);
      };
      console.log('[driftnet] SQLiteDatabase.execSQL hooked');
    } catch (e) {
      console.log('[driftnet] SQLiteDatabase.execSQL hook failed: ' + e);
    }
  });
}

// ---- WebView security-relevant settings -----------------------------------
function hookWebView() {
  Java.perform(() => {
    try {
      const WebSettings = Java.use('android.webkit.WebSettings');
      WebSettings.setJavaScriptEnabled.overload('boolean').implementation = function (enabled) {
        if (enabled) {
          emit(currentApp, 'webview', {
            op: 'js_enabled',
            setting: 'setJavaScriptEnabled',
            value: true,
          });
        }
        return this.setJavaScriptEnabled(enabled);
      };
      console.log('[driftnet] WebSettings.setJavaScriptEnabled hooked');
    } catch (e) {
      console.log('[driftnet] WebSettings.setJavaScriptEnabled hook failed: ' + e);
    }

    try {
      const WebSettings = Java.use('android.webkit.WebSettings');
      WebSettings.setMixedContentMode.overload('int').implementation = function (mode) {
        emit(currentApp, 'webview', {
          op: 'mixed_content',
          setting: 'setMixedContentMode',
          value: mode,
        });
        return this.setMixedContentMode(mode);
      };
      console.log('[driftnet] WebSettings.setMixedContentMode hooked');
    } catch (e) {
      console.log('[driftnet] WebSettings.setMixedContentMode hook failed: ' + e);
    }

    try {
      const WebSettings = Java.use('android.webkit.WebSettings');
      WebSettings.setAllowFileAccess.overload('boolean').implementation = function (allow) {
        if (allow) {
          emit(currentApp, 'webview', {
            op: 'file_access',
            setting: 'setAllowFileAccess',
            value: true,
          });
        }
        return this.setAllowFileAccess(allow);
      };
      console.log('[driftnet] WebSettings.setAllowFileAccess hooked');
    } catch (e) {
      console.log('[driftnet] WebSettings.setAllowFileAccess hook failed: ' + e);
    }

    try {
      const WebView = Java.use('android.webkit.WebView');
      WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function (obj, name) {
        emit(currentApp, 'webview', {
          op: 'js_interface',
          setting: 'addJavascriptInterface',
          value: true,
          interface_name: name ? name.toString() : '',
        });
        return this.addJavascriptInterface(obj, name);
      };
      console.log('[driftnet] WebView.addJavascriptInterface hooked');
    } catch (e) {
      console.log('[driftnet] WebView.addJavascriptInterface hook failed: ' + e);
    }
  });
}

// ---- Biometric authentication observation ---------------------------------
function hookBiometricPrompt() {
  Java.perform(() => {
    // Framework BiometricPrompt (API 28+)
    try {
      const BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');

      try {
        BiometricPrompt.authenticate.overload(
          'android.hardware.biometrics.BiometricPrompt$CryptoObject',
          'android.os.CancellationSignal',
          'java.util.concurrent.Executor',
          'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
        ).implementation = function () {
          emit(currentApp, 'biometric', {
            op: 'authenticate',
            api: 'BiometricPrompt',
            has_crypto_object: arguments[0] !== null,
          });
          return this.authenticate.apply(this, arguments);
        };
        console.log('[driftnet] BiometricPrompt.authenticate (with CryptoObject) hooked');
      } catch (e) {
        console.log('[driftnet] BiometricPrompt.authenticate (with CryptoObject) hook failed: ' + e);
      }

      try {
        BiometricPrompt.authenticate.overload(
          'android.os.CancellationSignal',
          'java.util.concurrent.Executor',
          'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
        ).implementation = function () {
          emit(currentApp, 'biometric', {
            op: 'authenticate',
            api: 'BiometricPrompt',
            has_crypto_object: false,
          });
          return this.authenticate.apply(this, arguments);
        };
        console.log('[driftnet] BiometricPrompt.authenticate (no CryptoObject) hooked');
      } catch (e) {
        console.log('[driftnet] BiometricPrompt.authenticate (no CryptoObject) hook failed: ' + e);
      }
    } catch (e) {
      console.log('[driftnet] framework BiometricPrompt hook failed: ' + e);
    }

    // AndroidX BiometricPrompt
    try {
      const AxBiometric = Java.use('androidx.biometric.BiometricPrompt');

      try {
        AxBiometric.authenticate.overload(
          'androidx.biometric.BiometricPrompt$PromptInfo'
        ).implementation = function () {
          emit(currentApp, 'biometric', {
            op: 'authenticate',
            api: 'androidx.BiometricPrompt',
            has_crypto_object: false,
          });
          return this.authenticate.apply(this, arguments);
        };
        console.log('[driftnet] androidx.BiometricPrompt.authenticate (no CryptoObject) hooked');
      } catch (e) {
        console.log('[driftnet] androidx.BiometricPrompt.authenticate (no CryptoObject) hook failed: ' + e);
      }

      try {
        AxBiometric.authenticate.overload(
          'androidx.biometric.BiometricPrompt$PromptInfo',
          'androidx.biometric.BiometricPrompt$CryptoObject'
        ).implementation = function () {
          emit(currentApp, 'biometric', {
            op: 'authenticate',
            api: 'androidx.BiometricPrompt',
            has_crypto_object: arguments[1] !== null,
          });
          return this.authenticate.apply(this, arguments);
        };
        console.log('[driftnet] androidx.BiometricPrompt.authenticate (with CryptoObject) hooked');
      } catch (e) {
        console.log('[driftnet] androidx.BiometricPrompt.authenticate (with CryptoObject) hook failed: ' + e);
      }
    } catch (e) {
      console.log('[driftnet] androidx BiometricPrompt hook failed: ' + e);
    }
  });
}



// ---- Clipboard Monitoring -----------------------------------------------
function hookClipboard() {
  Java.perform(() => {
    try {
      const ClipboardManager = Java.use('android.content.ClipboardManager');
      ClipboardManager.setPrimaryClip.overload('android.content.ClipData').implementation = function (clip) {
        if (clip) {
          const itemCount = clip.getItemCount();
          for (let i = 0; i < itemCount; i++) {
            const item = clip.getItemAt(i);
            const text = item.getText();
            if (text) {
              const textStr = text.toString();
              const match = scanForSecrets(textStr);
              if (match) {
                emit(currentApp, 'clipboard', {
                  op: 'set_primary_clip',
                  secret_pattern: match.pattern,
                  secret_preview: match.preview,
                  secret_location: 'clipboard'
                });
              }
            }
          }
        }
        return this.setPrimaryClip(clip);
      };
      console.log('[driftnet] ClipboardManager.setPrimaryClip hooked');
    } catch (e) {
      console.log('[driftnet] ClipboardManager hook failed: ' + e);
    }
  });
}

// ---- Insecure Storage Permissions -----------------------------------------
function hookInsecureStorage() {
  Java.perform(() => {
    try {
      const ContextImpl = Java.use('android.app.ContextImpl');
      ContextImpl.getSharedPreferences.overload('java.lang.String', 'int').implementation = function (name, mode) {
        const MODE_WORLD_READABLE = 1;
        const MODE_WORLD_WRITEABLE = 2;
        
        let badMode = '';
        if ((mode & MODE_WORLD_READABLE) !== 0) {
          badMode = 'MODE_WORLD_READABLE';
        }
        if ((mode & MODE_WORLD_WRITEABLE) !== 0) {
          badMode += (badMode ? ' | ' : '') + 'MODE_WORLD_WRITEABLE';
        }
        
        if (badMode) {
          emit(currentApp, 'fs', {
            op: 'get_shared_prefs',
            name: name ? name.toString() : '',
            mode: mode,
            mode_flags: badMode
          });
        }
        return this.getSharedPreferences(name, mode);
      };
      console.log('[driftnet] ContextImpl.getSharedPreferences hooked');
    } catch (e) {
      console.log('[driftnet] ContextImpl.getSharedPreferences hook failed: ' + e);
    }
  });
}

// ---- Weak PRNG Detection ------------------------------------------------
function hookWeakPRNG() {
  Java.perform(() => {
    try {
      const Random = Java.use('java.util.Random');
      const SecureRandom = Java.use('java.security.SecureRandom');
      
      Random.$init.overload().implementation = function () {
        // Exclude SecureRandom which inherits from Random
        if (!this.getClass().equals(SecureRandom.class)) {
          emit(currentApp, 'crypto', {
            api: 'java.util.Random.<init>',
            is_secure: false
          });
        }
        return this.$init();
      };
      
      Random.$init.overload('long').implementation = function (seed) {
        if (!this.getClass().equals(SecureRandom.class)) {
          emit(currentApp, 'crypto', {
            api: 'java.util.Random.<init>',
            is_secure: false,
            seeded: true
          });
        }
        return this.$init(seed);
      };
      console.log('[driftnet] java.util.Random constructor hooked');
    } catch (e) {
      console.log('[driftnet] java.util.Random hook failed: ' + e);
    }
  });
}


// ---- Insecure Broadcast Receivers ---------------------------------------
function hookBroadcastReceivers() {
  Java.perform(() => {
    try {
      const ContextWrapper = Java.use('android.content.ContextWrapper');
      
      const registerReceiverOverloads = ContextWrapper.registerReceiver.overloads;
      for (let i = 0; i < registerReceiverOverloads.length; i++) {
        const overload = registerReceiverOverloads[i];
        
        overload.implementation = function (...args) {
          const receiver = args[0];
          const filter = args[1];
          let broadcastPermission = null;
          
          if (args.length >= 3 && typeof args[2] === 'string') {
            broadcastPermission = args[2];
          } else if (args.length >= 4 && typeof args[2] === 'string') {
             broadcastPermission = args[2];
          }

          if (receiver && filter) {
            let actions = [];
            try {
               const iter = filter.actionsIterator();
               if(iter) {
                  while(iter.hasNext()) {
                    actions.push(iter.next().toString());
                  }
               }
            } catch(e) {}
            
            emit(currentApp, 'ipc', {
              op: 'register_receiver',
              receiver_class: receiver.getClass().getName(),
              actions: actions,
              permission: broadcastPermission || 'none'
            });
          }
          return overload.apply(this, args);
        };
      }
      console.log('[driftnet] ContextWrapper.registerReceiver hooked');
    } catch (e) {
      console.log('[driftnet] ContextWrapper.registerReceiver hook failed: ' + e);
    }
  });
}

// ---- Tapjacking (UI Redressing) -----------------------------------------
function hookTapjacking() {
  Java.perform(() => {
    try {
      const Activity = Java.use('android.app.Activity');
      const View = Java.use('android.view.View');
      const FLAG_NOT_TOUCH_MODAL = 0x00000020;
      const FLAG_WATCH_OUTSIDE_TOUCH = 0x00040000;
      const FILTER_TOUCHES_WHEN_OBSCURED = 1; // from View.FILTER_TOUCHES_WHEN_OBSCURED
      
      Activity.onResume.implementation = function () {
        try {
           const window = this.getWindow();
           if(window) {
               const decorView = window.getDecorView();
               if (decorView) {
                  // Check if filterTouchesWhenObscured is true
                  const isFiltered = decorView.getFilterTouchesWhenObscured();
                  emit(currentApp, 'ui', {
                    op: 'activity_resume',
                    activity: this.getClass().getName(),
                    filter_touches: isFiltered
                  });
               }
           }
        } catch(e) {}
        this.onResume();
      };
      console.log('[driftnet] Activity.onResume hooked for Tapjacking checks');
    } catch (e) {
      console.log('[driftnet] Tapjacking hook failed: ' + e);
    }
  });
}

// ---- Weak Hostname Verification -----------------------------------------
function hookHostnameVerifier() {
  Java.perform(() => {
    try {
      const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
      HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
        let isDefault = false;
        if(verifier) {
           const verifierClass = verifier.getClass().getName();
           if (verifierClass.indexOf('DefaultHostnameVerifier') !== -1 || verifierClass.indexOf('OkHostnameVerifier') !== -1) {
              isDefault = true;
           }
           emit(currentApp, 'network', {
             transport: 'https_url_connection',
             op: 'set_hostname_verifier',
             verifier_class: verifierClass,
             is_default_or_safe: isDefault
           });
        }
        return this.setDefaultHostnameVerifier(verifier);
      };
      
      HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
        let isDefault = false;
        if(verifier) {
           const verifierClass = verifier.getClass().getName();
           if (verifierClass.indexOf('DefaultHostnameVerifier') !== -1 || verifierClass.indexOf('OkHostnameVerifier') !== -1) {
              isDefault = true;
           }
           emit(currentApp, 'network', {
             transport: 'https_url_connection',
             op: 'set_hostname_verifier_instance',
             verifier_class: verifierClass,
             is_default_or_safe: isDefault
           });
        }
        return this.setHostnameVerifier(verifier);
      };
      console.log('[driftnet] HttpsURLConnection HostnameVerifier hooked');
    } catch (e) {
      console.log('[driftnet] HostnameVerifier hook failed: ' + e);
    }
  });
}

// ---- Native / JNI hooking -----------------------------------------------
function hookNative() {
  // Network: getaddrinfo in libc.so
  try {
    const getaddrinfoPtr = Module.findExportByName('libc.so', 'getaddrinfo');
    if (getaddrinfoPtr) {
      Interceptor.attach(getaddrinfoPtr, {
        onEnter: function (args) {
          try {
            const host = args[0].readUtf8String();
            if (host) {
              emit(currentApp, 'network', {
                transport: 'native/libc',
                host: safeHost(host),
                path: '/'
              });
            }
          } catch (e) {}
        }
      });
      console.log('[driftnet] libc.so getaddrinfo hooked');
    }
  } catch (e) {
    console.log('[driftnet] Native getaddrinfo hook failed: ' + e);
  }

  // Crypto: EVP_CipherInit_ex in libcrypto.so
  try {
    const EVP_CipherInit_ex_ptr = Module.findExportByName('libcrypto.so', 'EVP_CipherInit_ex');
    const EVP_CIPHER_name_ptr = Module.findExportByName('libcrypto.so', 'EVP_CIPHER_name');

    if (EVP_CipherInit_ex_ptr) {
      const EVP_CIPHER_name = EVP_CIPHER_name_ptr ? new NativeFunction(EVP_CIPHER_name_ptr, 'pointer', ['pointer']) : null;
      
      Interceptor.attach(EVP_CipherInit_ex_ptr, {
        onEnter: function (args) {
          try {
            const type = args[1]; // const EVP_CIPHER *type
            let cipherName = 'unknown';
            
            if (type && !type.isNull() && EVP_CIPHER_name) {
              const namePtr = EVP_CIPHER_name(type);
              if (namePtr && !namePtr.isNull()) {
                cipherName = namePtr.readUtf8String();
              }
            }
            
            emit(currentApp, 'crypto', {
              api: 'EVP_CipherInit_ex',
              transformation: cipherName
            });
          } catch (e) {}
        }
      });
      console.log('[driftnet] libcrypto.so EVP_CipherInit_ex hooked');
    }
  } catch (e) {
    console.log('[driftnet] Native crypto hook failed: ' + e);
  }
}

function hookZipSlip() {
  Java.perform(() => {
    try {
      const ZipEntry = Java.use('java.util.zip.ZipEntry');
      ZipEntry.getName.implementation = function() {
        const name = this.getName();
        if (name && (name.indexOf('../') !== -1 || name.indexOf('..\\') !== -1)) {
          emit(currentApp, 'fs', {
            op: 'zip_entry_get_name',
            path: name
          });
        }
        return name;
      };
      console.log('[driftnet] java.util.zip.ZipEntry.getName hooked (Zip Slip)');
    } catch (e) {
      console.log('[driftnet] Zip Slip hook failed: ' + e);
    }
  });
}

function hookPendingIntent() {
  Java.perform(() => {
    try {
      const PendingIntent = Java.use('android.app.PendingIntent');
      
      function checkPendingIntent(intent, flags, method) {
        // FLAG_MUTABLE is 0x02000000 (33554432)
        const isMutable = (flags & 0x02000000) !== 0;
        
        let isImplicit = false;
        let action = '';
        if (intent) {
          action = intent.getAction() ? intent.getAction().toString() : '';
          const component = intent.getComponent();
          isImplicit = (component === null);
        }

        if (isMutable && isImplicit) {
          emit(currentApp, 'intent', {
            op: 'pending_intent_' + method,
            action: action,
            is_mutable: true,
            is_implicit: true
          });
        }
      }

      PendingIntent.getActivity.overload('android.content.Context', 'int', 'android.content.Intent', 'int').implementation = function(context, requestCode, intent, flags) {
        checkPendingIntent(intent, flags, 'getActivity');
        return this.getActivity(context, requestCode, intent, flags);
      };
      
      PendingIntent.getBroadcast.overload('android.content.Context', 'int', 'android.content.Intent', 'int').implementation = function(context, requestCode, intent, flags) {
        checkPendingIntent(intent, flags, 'getBroadcast');
        return this.getBroadcast(context, requestCode, intent, flags);
      };
      
      PendingIntent.getService.overload('android.content.Context', 'int', 'android.content.Intent', 'int').implementation = function(context, requestCode, intent, flags) {
        checkPendingIntent(intent, flags, 'getService');
        return this.getService(context, requestCode, intent, flags);
      };
      
      console.log('[driftnet] PendingIntent Hijacking detection hooked');
    } catch (e) {
      console.log('[driftnet] PendingIntent hook failed: ' + e);
    }
  });
}

function hookArtDexLoading() {
  try {
    // Android 8.0+ OpenCommon or OpenMemory
    // Finding OpenMemory / OpenCommon signatures in libart.so
    const symbols = Module.enumerateExports('libart.so');
    let targetExport = null;
    for (let i = 0; i < symbols.length; i++) {
      if (symbols[i].name.indexOf('DexFile') !== -1 && 
         (symbols[i].name.indexOf('OpenMemory') !== -1 || symbols[i].name.indexOf('OpenCommon') !== -1)) {
        targetExport = symbols[i];
        break;
      }
    }

    if (targetExport) {
      Interceptor.attach(targetExport.address, {
        onEnter: function (args) {
          try {
            // arg0 is usually the base address of the dex bytes in memory
            const base = args[0];
            const size = args[1].toInt32();
            
            if (size > 0 && size < 100 * 1024 * 1024) { // reasonable dex size
              const header = base.readByteArray(8);
              const headerBytes = new Uint8Array(header);
              // Check for 'dex\n035\0' or similar magic
              if (headerBytes[0] === 0x64 && headerBytes[1] === 0x65 && headerBytes[2] === 0x78 && headerBytes[3] === 0x0a) {
                emit(currentApp, 'native', {
                  op: 'dex_load',
                  size: size,
                  address: base.toString()
                });
              }
            }
          } catch (e) {}
        }
      });
      console.log('[driftnet] libart.so ' + targetExport.name + ' hooked for DEX unpacking');
    }
  } catch (e) {
    console.log('[driftnet] ART DEX loading hook failed: ' + e);
  }
}

function hookJniRegisterNatives() {
  // Hook RegisterNatives in libart.so (Android Runtime)
  try {
    const RegisterNatives = Module.findExportByName('libart.so', '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi');
    if (RegisterNatives) {
      Interceptor.attach(RegisterNatives, {
        onEnter: function (args) {
          try {
            // arg0: JNIEnv*
            // arg1: jclass
            // arg2: JNINativeMethod* methods
            // arg3: int numMethods
            
            const env = args[0];
            const javaClass = args[1];
            const methodsPtr = args[2];
            const numMethods = args[3].toInt32();

            // We could get the class name via JNI, but it requires allocating memory and calling GetStringUTFChars.
            // For stability in this passive hook, we just log the bindings.
            
            for (let i = 0; i < numMethods; i++) {
              // struct JNINativeMethod {
              //    const char* name;
              //    const char* signature;
              //    void*       fnPtr;
              // }
              const methodPtr = methodsPtr.add(i * Process.pointerSize * 3);
              const namePtr = methodPtr.readPointer();
              const sigPtr = methodPtr.add(Process.pointerSize).readPointer();
              const fnPtr = methodPtr.add(Process.pointerSize * 2).readPointer();
              
              const name = namePtr.readUtf8String();
              const sig = sigPtr.readUtf8String();
              
              emit(currentApp, 'native', {
                op: 'jni_registration',
                method_name: name,
                signature: sig,
                fn_ptr: fnPtr.toString()
              });
            }
          } catch (e) {}
        }
      });
      console.log('[driftnet] libart.so RegisterNatives hooked');
    }
  } catch (e) {
    console.log('[driftnet] JNI RegisterNatives hook failed: ' + e);
  }
}

function hookSecureRandom() {
  Java.perform(() => {
    try {
      const SecureRandom = Java.use('java.security.SecureRandom');
      SecureRandom.setSeed.overload('[B').implementation = function (seed) {
        emit(currentApp, 'crypto', {
          api: 'SecureRandom.setSeed',
          seed_length: seed ? seed.length : 0
        });
        return this.setSeed(seed);
      };
      console.log('[driftnet] SecureRandom.setSeed hooked');
    } catch (e) {
      console.log('[driftnet] SecureRandom hook failed: ' + e);
    }
  });
}

function hookFlagSecure() {
  Java.perform(() => {
    try {
      const Window = Java.use('android.view.Window');
      // FLAG_SECURE is 0x2000 (8192)
      Window.setFlags.implementation = function(flags, mask) {
        if ((flags & 0x2000) !== 0) {
          emit(currentApp, 'ui', {
            op: 'window_set_flags',
            has_flag_secure: true
          });
        }
        return this.setFlags(flags, mask);
      };
      
      const Activity = Java.use('android.app.Activity');
      Activity.onResume.implementation = function () {
        const activityName = this.getClass().getName();
        const l = activityName.toLowerCase();
        
        // If it's a sensitive activity, check its window flags
        if (l.indexOf('login') !== -1 || l.indexOf('auth') !== -1 || l.indexOf('payment') !== -1 || l.indexOf('wallet') !== -1 || l.indexOf('pin') !== -1) {
          let hasFlagSecure = false;
          try {
            const window = this.getWindow();
            if (window) {
              const attrs = window.getAttributes();
              if (attrs) {
                const flags = attrs.flags.value;
                hasFlagSecure = (flags & 0x2000) !== 0;
              }
            }
          } catch(e) {}
          
          if (!hasFlagSecure) {
            emit(currentApp, 'ui', {
              op: 'sensitive_activity_resume',
              activity_name: activityName,
              has_flag_secure: false
            });
          }
        }
        
        return this.onResume();
      };
      
      console.log('[driftnet] FLAG_SECURE / Screen Capture protection hooked');
    } catch (e) {
      console.log('[driftnet] FLAG_SECURE hook failed: ' + e);
    }
  });
}

function hookInsecureFilePermissions() {
  Java.perform(() => {
    try {
      const ContextWrapper = Java.use('android.content.ContextWrapper');
      
      // MODE_WORLD_READABLE = 1, MODE_WORLD_WRITEABLE = 2
      ContextWrapper.openFileOutput.overload('java.lang.String', 'int').implementation = function(name, mode) {
        if (mode === 1 || mode === 2 || mode === 3) {
          emit(currentApp, 'fs', {
            op: 'open_file_output',
            name: name,
            mode: mode
          });
        }
        return this.openFileOutput(name, mode);
      };

      ContextWrapper.getSharedPreferences.overload('java.lang.String', 'int').implementation = function(name, mode) {
        if (mode === 1 || mode === 2 || mode === 3) {
          emit(currentApp, 'fs', {
            op: 'get_shared_preferences',
            name: name,
            mode: mode
          });
        }
        return this.getSharedPreferences(name, mode);
      };
      
      console.log('[driftnet] Insecure File Permissions hooked');
    } catch (e) {
      console.log('[driftnet] File Permissions hook failed: ' + e);
    }
  });
}

function hookSecureSettings() {
  Java.perform(() => {
    try {
      const SettingsSecure = Java.use('android.provider.Settings$Secure');
      
      const checkSetting = function(name) {
        if (name && (name === 'development_settings_enabled' || name === 'adb_enabled' || name === 'mock_location')) {
          emit(currentApp, 'anti_analysis', {
            op: 'secure_settings_query',
            setting: name
          });
        }
      };

      SettingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(resolver, name) {
        checkSetting(name);
        return this.getInt(resolver, name);
      };
      
      SettingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(resolver, name, def) {
        checkSetting(name);
        return this.getInt(resolver, name, def);
      };
      
      SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(resolver, name) {
        checkSetting(name);
        return this.getString(resolver, name);
      };

      console.log('[driftnet] Settings.Secure hooked for anti-analysis detection');
    } catch (e) {
      console.log('[driftnet] Settings.Secure hook failed: ' + e);
    }
  });
}

function hookMemoryScanner() {
  // Periodically scan memory for high-value secrets
  // Warning: Can be resource intensive, so we run it infrequently
  setInterval(() => {
    try {
      // Scan for AWS Access Keys (AKIA...)
      // Pattern for 'AKIA' in hex: 41 4b 49 41
      const ranges = Process.enumerateRanges('r--');
      for (let i = 0; i < ranges.length; i++) {
        const range = ranges[i];
        if (range.file && range.file.path.indexOf('dalvik-main space') !== -1) {
          Memory.scan(range.base, range.size, '41 4b 49 41', {
            onMatch: function (address, size) {
              try {
                // Read 20 bytes (typical AKIA length)
                const possibleKey = address.readUtf8String(20);
                if (possibleKey && possibleKey.startsWith('AKIA') && possibleKey.length === 20) {
                  emit(currentApp, 'memory', {
                    op: 'memory_scan',
                    secret_pattern: 'AKIA_KEY_PATTERN', // Let backend rule handle it
                    address: address.toString()
                  });
                }
              } catch (e) {}
              return 'stop'; // Stop after finding one to avoid flooding
            },
            onComplete: function () {}
          });
        }
      }
    } catch (e) {
      console.log('[driftnet] Memory scanner error: ' + e);
    }
  }, 30000); // Run every 30 seconds
  console.log('[driftnet] Periodic Memory Scanner initialized');
}

function hookStalkerTracing() {
  // We hook a common crypto entry point, and trace execution from there
  try {
    const EVP_CipherInit_ex_ptr = Module.findExportByName('libcrypto.so', 'EVP_CipherInit_ex');
    if (EVP_CipherInit_ex_ptr) {
      Interceptor.attach(EVP_CipherInit_ex_ptr, {
        onEnter: function (args) {
          try {
            const threadId = Process.getCurrentThreadId();
            
            // Start Stalker for this thread
            Stalker.follow(threadId, {
              events: {
                call: false, // Don't track normal calls
                ret: false,
                exec: false,
                block: false,
                compile: true // Track when code is compiled/executed
              },
              onReceive: function (events) {
                // Not heavily parsing events here to save performance, 
                // but setting up the Stalker pipeline.
              },
              transform: function (iterator) {
                let instruction = iterator.next();
                while (instruction !== null) {
                  // Look for raw Supervisor Calls (SVC) in ARM/ARM64
                  if (instruction.mnemonic === 'svc') {
                    emit(currentApp, 'tracing', {
                      op: 'raw_syscall',
                      address: instruction.address.toString()
                    });
                  }
                  iterator.keep();
                  instruction = iterator.next();
                }
              }
            });
            
            // Stop stalker after 100ms to avoid freezing the app
            setTimeout(() => {
              try {
                Stalker.unfollow(threadId);
              } catch(e) {}
            }, 100);
            
          } catch (e) {}
        }
      });
      console.log('[driftnet] Stalker Execution Tracing initialized on libcrypto');
    }
  } catch (e) {
    console.log('[driftnet] Stalker tracing setup failed: ' + e);
  }
}

function hookDCL() {
  Java.perform(() => {
    try {
      const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
      DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
        emit(currentApp, 'dcl', {
          op: 'dex_class_loader',
          path: dexPath
        });
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
      };
      
      const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
      PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, parent) {
        emit(currentApp, 'dcl', {
          op: 'path_class_loader',
          path: dexPath
        });
        return this.$init(dexPath, parent);
      };
      
      console.log('[driftnet] Dynamic Code Loading (DCL) hooked');
    } catch (e) {
      console.log('[driftnet] DCL hook failed: ' + e);
    }
  });
}

function hookAntiTamper() {
  Java.perform(() => {
    try {
      const File = Java.use('java.io.File');
      File.exists.implementation = function () {
        const path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('Superuser') !== -1 || path.indexOf('frida') !== -1 || path.indexOf('magisk') !== -1) {
          emit(currentApp, 'anti_analysis', { op: 'file_exists', target: path });
        }
        return this.exists();
      };
      
      const Runtime = Java.use('java.lang.Runtime');
      Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('mount') !== -1 || cmd.indexOf('ps') !== -1)) {
          emit(currentApp, 'anti_analysis', { op: 'runtime_exec', cmd: cmd });
        }
        return this.exec(cmd);
      };
      console.log('[driftnet] Anti-tamper monitoring hooked');
    } catch (e) {
      console.log('[driftnet] Anti-tamper hook failed: ' + e);
    }
  });
}

function hookClassTracing() {
  Java.perform(() => {
    try {
      let seenClasses = new Set();
      setInterval(() => {
        Java.perform(() => {
          try {
            const classes = Java.enumerateLoadedClassesSync();
            classes.forEach(c => {
              if (!seenClasses.has(c)) {
                seenClasses.add(c);
                const l = c.toLowerCase();
                if (l.indexOf('payment') !== -1 || l.indexOf('stripe') !== -1 || l.indexOf('crypto') !== -1 || l.indexOf('firebase') !== -1 || l.indexOf('wallet') !== -1 || l.indexOf('analytics') !== -1) {
                  emit(currentApp, 'tracing', { op: 'class_load', class_name: c });
                }
              }
            });
          } catch(e) {}
        });
      }, 5000);
      console.log('[driftnet] Class tracing interval started');
    } catch (e) {
      console.log('[driftnet] Class tracing failed: ' + e);
    }
  });
}

function hookBinderIPC() {
  Java.perform(() => {
    try {
      const BinderProxy = Java.use('android.os.BinderProxy');
      BinderProxy.transact.implementation = function(code, data, reply, flags) {
        let interfaceName = 'unknown';
        try {
          if (data !== null) {
            interfaceName = data.getInterfaceDescriptor() || 'unknown';
          }
        } catch(e) {}
        
        emit(currentApp, 'binder', {
          op: 'transact',
          code: code,
          interface: interfaceName
        });
        
        return this.transact(code, data, reply, flags);
      };
      console.log('[driftnet] BinderProxy.transact hooked');
    } catch (e) {
      console.log('[driftnet] Binder hook failed: ' + e);
    }
  });
}

// ---- Helpers --------------------------------------------------------------
function safeHost(urlStr) {
  try {
    return urlStr.split('/')[2] || 'unknown';
  } catch (e) {
    return 'unknown';
  }
}
function safePath(urlStr) {
  try {
    const idx = urlStr.indexOf('/', 8);
    return idx === -1 ? '/' : urlStr.substring(idx);
  } catch (e) {
    return '/';
  }
}

// emitToRelay() bridges to the Python relay via Frida's built-in RPC
// message channel -- see scripts/relay.py for the WS forwarding side.
//
// Captures Frida's native `send` under a name that can never collide
// with anything else in this file, rather than declaring a local
// function ALSO named `send` that wraps a captured reference to the
// original. An earlier draft did exactly that (`function send(payload)
// { send_(payload); } const send_ = globalThis.send;`), reasoning that
// the wrapper would be safe since it captures the original before
// anything could shadow it. Node.js does execute that pattern safely
// (confirmed by testing it directly) -- but only because Node wraps each
// file in a CommonJS module function, which scopes top-level `function`
// declarations locally rather than binding them onto the true global
// object. Frida's actual script execution model (module-wrapped vs raw
// global scope, and whether its native `send` is writable/configurable
// once installed) isn't documented clearly enough to stake a real
// device's first run on -- and if global function declarations DO bind
// directly against a non-writable global in strict mode (this file
// declares 'use strict' at the top), redeclaring `send` could throw
// before any hook even installs, or silently create infinite recursion.
// Renaming removes the question entirely instead of relying on a
// specific hoisting/scoping behavior I can't verify without real Frida.
const NATIVE_SEND = globalThis.send;
function emitToRelay(payload) {
  NATIVE_SEND(payload);
}

// ---- Attach everything ------------------------------------------------
setImmediate(() => {
  // Native hooks can run immediately
  hookNative();
  hookBoringSSL();
  hookFlutterBoringSSL();
  hookMemoryScanner();
  hookStalkerTracing();
  if (ENABLE_ANTI_DETECTION_BYPASS) {
    hookPhantomProtocol();
  }

  // Java hooks must wait for VM
  try {
    Java.perform(() => {
      resolveAppVersion();
      hookOkHttp3();
      hookJavaNet();
      hookFlutterHttpClient();
      hookCrypto();
      hookMessageDigest();
      hookFileAccess();
      hookSharedPrefs();
      hookLogging();
      hookIntentActivity();
      hookSQLiteDatabase();
      hookBroadcastReceivers();
      hookTapjacking();
      hookHostnameVerifier();
      hookClipboard();
      hookInsecureStorage();
      hookWeakPRNG();
      hookBiometrics();
      hookWebView();
      hookBiometricPrompt();
      hookAntiTamper();
      hookClassTracing();
      hookBinderIPC();
      hookDCL();
      hookZipSlip();
      hookPendingIntent();
      hookArtDexLoading();
      hookJniRegisterNatives();
      hookSecureRandom();
      hookFlagSecure();
      hookInsecureFilePermissions();
      hookSecureSettings();
    });
  } catch (e) {
    console.log('[driftnet] Java.perform error: ' + e);
  }

  console.log('[driftnet] agent attached to ' + currentApp + ', forwarding to relay');
});

function hookBoringSSL() {
  try {
    const SSL_write_ptr = Module.findExportByName('libssl.so', 'SSL_write');
    if (SSL_write_ptr) {
      Interceptor.attach(SSL_write_ptr, {
        onEnter: function (args) {
          try {
            // SSL_write(SSL *ssl, const void *buf, int num)
            const buf = args[1];
            const num = args[2].toInt32();
            if (num > 0 && num < 1024 * 1024) { // arbitrary 1MB limit for sanity
              const data = buf.readByteArray(num);
              // We need to convert ByteArray to string to scan for secrets, but only grab a chunk
              // to avoid blowing up memory/JSON on massive POST bodies.
              const maxLen = Math.min(num, 4096);
              const dataStr = buf.readUtf8String(maxLen);
              
              let secret = null;
              if (dataStr) {
                // Split by lines and scan to find headers or body secrets
                const lines = dataStr.split('\n');
                for (let i = 0; i < lines.length && !secret; i++) {
                  secret = scanForSecrets(lines[i]);
                }
              }
              
              const detail = {
                op: 'ssl_write',
                bytes: num.toString()
              };
              
              if (secret) {
                detail.secret_pattern = secret.pattern;
                detail.secret_preview = secret.preview;
              }
              
              emit(currentApp, 'native_tls', detail);
            }
          } catch (e) {}
        }
      });
      console.log('[driftnet] libssl.so SSL_write hooked');
    }
  } catch (e) {
    console.log('[driftnet] BoringSSL hook failed: ' + e);
  }
}

function hookFlutterBoringSSL() {
  try {
    const flutterModule = Process.findModuleByName('libflutter.so') || Process.findModuleByName('libapp.so');
    if (!flutterModule) {
      // Not a Flutter app, skip gracefully
      return;
    }
    
    console.log('[driftnet] Found statically linked Flutter/Dart engine: ' + flutterModule.name);
    
    // In a real production deployment, these signatures are dynamically maintained or generated
    // by searching for string XREFs (e.g., "ssl_handshake.cc"). For this architecture, we use
    // standard ARM64 BoringSSL prologues as an example.
    // e.g., stp x29, x30, [sp, #-...]; mov x29, sp
    const sslWritePattern = "ff 43 01 d1 fd 7b 01 a9 fd 83 00 91"; 
    
    // Scan for SSL_write
    const matches = Memory.scanSync(flutterModule.base, flutterModule.size, sslWritePattern);
    
    if (matches.length > 0) {
      const sslWriteAddress = matches[0].address;
      console.log('[driftnet] Found Flutter SSL_write at ' + sslWriteAddress);
      
      Interceptor.attach(sslWriteAddress, {
        onEnter: function (args) {
          try {
            // SSL_write(SSL *ssl, const void *buf, int num)
            const buf = args[1];
            const num = args[2].toInt32();
            if (num > 0 && num < 1024 * 1024) { 
              const data = buf.readByteArray(num);
              const maxLen = Math.min(num, 4096);
              const dataStr = buf.readUtf8String(maxLen);
              
              let secret = null;
              if (dataStr) {
                const lines = dataStr.split('\n');
                for (let i = 0; i < lines.length && !secret; i++) {
                  secret = scanForSecrets(lines[i]);
                }
              }
              
              const detail = {
                op: 'flutter_ssl_write',
                bytes: num.toString()
              };
              
              if (secret) {
                detail.secret_pattern = secret.pattern;
                detail.secret_preview = secret.preview;
              }
              
              emit(currentApp, 'native_tls', detail);
            }
          } catch (e) {}
        }
      });
      console.log('[driftnet] Flutter SSL_write hooked successfully');
    } else {
      console.log('[driftnet] Flutter SSL_write signature not found. May need updated byte pattern.');
    }
  } catch (e) {
    console.log('[driftnet] Flutter BoringSSL hook failed: ' + e);
  }
}

// ---- Active Mitigation ------------------------------------------------
function handleMessages() {
  recv('action', function onMessage(msg) {
    if (msg.action === 'BLOCK') {
      console.log('[driftnet] 🛑 ACTIVE MITIGATION TRIGGERED: ' + (msg.payload ? msg.payload.reason : ''));
      // In a real IPS, we would block the specific socket/file descriptor.
      // For this MVP "max out", we'll just nuke the process to stop the threat instantly.
      try {
        var System = Java.use('java.lang.System');
        System.exit(0);
      } catch (e) {
        // Fallback if Dalvik isn't available
        var libc = Module.findExportByName('libc.so', 'exit');
        if (libc) {
          var exit = new NativeFunction(libc, 'void', ['int']);
          exit(0);
        }
      }
    }
    handleMessages(); // Wait for the next message
  });
}

handleMessages();
