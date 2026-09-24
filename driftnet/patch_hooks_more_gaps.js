const fs = require('fs');

let hooks = fs.readFileSync('agent/hooks.js', 'utf8');

const newHooksCode = `
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
`;

hooks = hooks.replace('// ---- Native / JNI hooking -----------------------------------------------', newHooksCode + '\n// ---- Native / JNI hooking -----------------------------------------------');

hooks = hooks.replace('hookNative();', 'hookNative();\n  hookBroadcastReceivers();\n  hookTapjacking();\n  hookHostnameVerifier();');

fs.writeFileSync('agent/hooks.js', hooks);
console.log('More gaps patched');
