const fs = require('fs');

let hooks = fs.readFileSync('agent/hooks.js', 'utf8');

const newHooksCode = `
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
`;

hooks = hooks.replace('// ---- Native / JNI hooking -----------------------------------------------', newHooksCode + '\n// ---- Native / JNI hooking -----------------------------------------------');

hooks = hooks.replace('hookNative();', 'hookNative();\n  hookClipboard();\n  hookInsecureStorage();\n  hookWeakPRNG();');

fs.writeFileSync('agent/hooks.js', hooks);
console.log('More hooks patched');
