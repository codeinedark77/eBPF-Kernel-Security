const fs = require('fs');

let hooks = fs.readFileSync('agent/hooks.js', 'utf8');

const sqliteHookAddition = `
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
`;

hooks = hooks.replace('// ---- SQLite database observation ------------------------------------------\nfunction hookSQLiteDatabase() {\n  Java.perform(() => {', '// ---- SQLite database observation ------------------------------------------\nfunction hookSQLiteDatabase() {\n  Java.perform(() => {' + sqliteHookAddition);

const nativeHooks = `
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
`;

hooks = hooks.replace('// ---- Helpers --------------------------------------------------------------', nativeHooks + '\n// ---- Helpers --------------------------------------------------------------');
hooks = hooks.replace('hookSQLiteDatabase();', 'hookSQLiteDatabase();\n  hookNative();');

fs.writeFileSync('agent/hooks.js', hooks);
console.log('Hooks patched');
