# Mobile Application Testing

## 1. Android — acquisition

```bash
# From device
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/.../base.apk

# From Play Store mirror
apkpure / apkmirror, or
gplaycli -d com.target.app

# Split APKs
adb shell pm path com.target.app   # multiple base/split apks
# merge with APKEditor or install all with adb install-multiple
```

## 2. Static analysis

```bash
apktool d app.apk -o app-decoded          # manifest, resources, smali
jadx-gui app.apk                          # decompiled Java
apkanalyzer manifest print app.apk
unzip -l app.apk | grep -E 'assets|res/raw|lib/'

# Secrets
grep -rInE 'api[_-]?key|secret|token|firebase|amazonaws|BEGIN RSA' app-decoded/
trufflehog filesystem app-decoded/
strings lib/arm64-v8a/*.so | grep -iE 'http|key|secret'

# Native
ghidra / r2 on lib/*.so
```

Check in `AndroidManifest.xml`:

- [ ] `android:debuggable="true"`
- [ ] `android:allowBackup="true"` → `adb backup`
- [ ] `android:exported="true"` on activities/services/receivers/providers
- [ ] Deep links / intent filters with custom schemes
- [ ] `usesCleartextTraffic="true"`
- [ ] Permissions beyond need
- [ ] Network security config with user CA trusted

## 3. Dynamic analysis

```bash
# Emulator with root
emulator -avd pixel -writable-system
adb root; adb remount

# Frida
frida-ps -U
frida -U -f com.target.app -l script.js --no-pause

# Objection
objection -g com.target.app explore
# android sslpinning disable
# android root disable
# android hooking list activities
```

**SSL pinning bypass:** `frida-multiple-unpinning`, `objection android sslpinning disable`, or patch the network security config. For Flutter apps use `reFlutter`; for React Native hook `okhttp`/`NSURLSession` equivalents.

**Root / emulator detection:** hook `RootBeer`, `SafetyNet`/`Play Integrity`, `Build.TAGS`, `File.exists` on su paths.

## 4. Component and IPC testing

```bash
drozer console connect
run app.package.attacksurface com.target.app
run app.activity.info -a com.target.app
run app.provider.info -a com.target.app
run app.service.info -a com.target.app
run app.broadcast.info -a com.target.app

# Direct intent
adb shell am start -n com.target.app/.AdminActivity
adb shell am start -a android.intent.action.VIEW -d "target://reset?token=x"
adb shell content query --uri content://com.target.app.provider/users
```

Look for: exported admin activities, content providers without permission, path traversal in providers, intent redirection, pending intent hijacking, task hijacking (StrandHogg), tapjacking via overlay.

## 5. WebView

- `setJavaScriptEnabled(true)` + `addJavascriptInterface` → bridge RCE on old API levels
- `setAllowFileAccess(true)` + `loadUrl` with user input → local file read
- `setAllowUniversalAccessFromFileURLs(true)` → SOP bypass
- Deep link → WebView with `javascript:` or `file://`
- Check `shouldOverrideUrlLoading` for missing scheme validation

## 6. Backend and cloud

- Firebase: `https://<project>.firebaseio.com/.json`, `https://firebaseio.com/.json?auth=`, storage bucket listing
- Hardcoded API endpoints → test as web targets
- Mobile API often has weaker auth: no rate limit, long-lived tokens, `X-Device-Id` trust
- Certificate pinning bypassed → replay traffic through Burp

## 7. iOS

```bash
# Decrypt from jailbroken device
frida-ios-dump -u <udid> com.target.app
# or
bagbak com.target.app

class-dump -H AppBinary -o headers/
otool -L AppBinary
plutil -p Info.plist
```

- Keychain: `objection -g com.target.app explore` → `ios keychain dump`
- Data protection class per file, `NSFileProtection`
- URL schemes and universal links
- Jailbreak detection: hook `fileExistsAtPath`, `canOpenURL`, `stat`
- Biometric bypass: hook `LAContext evaluatePolicy`
- Pasteboard leakage, screenshot caching, background snapshots
- ATS (`NSAppTransportSecurity`) exceptions

## 8. Reporting

Mobile findings map to the same `findings.yaml` schema. Add the app version and build number to `asset`, and include the device/OS in preconditions — a finding on Android 9 may not reproduce on 14.

## 9. Checklist

- [ ] APK/IPA acquired and hashed
- [ ] Manifest reviewed for exported components
- [ ] Secrets scanned in code, resources, native libs
- [ ] Traffic intercepted with pinning bypassed
- [ ] Every exported component exercised
- [ ] Deep links and intent redirection tested
- [ ] Firebase / cloud endpoints checked
- [ ] Local storage, keychain, logs reviewed
- [ ] Root/jailbreak and tamper detection assessed
