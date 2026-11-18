#!/usr/bin/env bash
# Builds the Anomaly Watch APK without Gradle:
#   aapt2 (resources) -> javac -> d8 (dex) -> zipalign -> apksigner
#
# Requires the Android SDK (build-tools 34.0.0, platform android-34) and a JDK.
set -euo pipefail
cd "$(dirname "$0")"

MIN_SDK=26
TARGET_SDK=34
VERSION_CODE=2
VERSION_NAME=1.1

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$LOCALAPPDATA/Android/Sdk}}"
# 36.0.0: its d8 handles some generated inner classes that 34.0.0's d8 crashes on.
BT="$SDK/build-tools/36.0.0"

if [ ! -d "$BT" ]; then
  echo "build-tools 36.0.0 not found at $BT" >&2
  exit 1
fi

ANDROID_JAR=""
for candidate in \
  "$SDK/platforms/android-$TARGET_SDK/android.jar" \
  "$SDK/platforms/android-$TARGET_SDK-2/android.jar" \
  "$SDK"/platforms/*/android.jar; do
  if [ -f "$candidate" ]; then ANDROID_JAR="$candidate"; break; fi
done
if [ -z "$ANDROID_JAR" ]; then
  echo "no android.jar found under $SDK/platforms" >&2
  exit 1
fi

# --- locate a JDK -----------------------------------------------------------
pick() {
  if [ -x "$1" ]; then printf '%s' "$1"
  elif [ -x "$1.exe" ]; then printf '%s' "$1.exe"
  else printf '%s' "$1"; fi
}

JDK="${JAVA_HOME:-}"
if [ ! -x "$JDK/bin/javac" ] && [ ! -x "$JDK/bin/javac.exe" ]; then
  JDK=""
  for candidate in \
    "/c/Program Files/Android/Android Studio/jbr" \
    "/c/Program Files/Eclipse Adoptium"/* \
    "/c/Program Files/Microsoft/jdk"*; do
    if [ -x "$candidate/bin/javac.exe" ] || [ -x "$candidate/bin/javac" ]; then
      JDK="$candidate"
      break
    fi
  done
fi
if [ -z "$JDK" ]; then
  echo "no JDK found (set JAVA_HOME)" >&2
  exit 1
fi

JAVAC=$(pick "$JDK/bin/javac")
JAVA=$(pick "$JDK/bin/java")
JARTOOL=$(pick "$JDK/bin/jar")
KEYTOOL=$(pick "$JDK/bin/keytool")
AAPT2=$(pick "$BT/aapt2")
ZIPALIGN=$(pick "$BT/zipalign")

OUT=build
rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/dex"

echo "== aapt2 compile/link"
"$AAPT2" compile --dir res -o "$OUT/res.zip"
"$AAPT2" link -o "$OUT/base.apk" \
  -I "$ANDROID_JAR" \
  --manifest AndroidManifest.xml \
  --java "$OUT/gen" \
  --min-sdk-version "$MIN_SDK" \
  --target-sdk-version "$TARGET_SDK" \
  --version-code "$VERSION_CODE" \
  --version-name "$VERSION_NAME" \
  "$OUT/res.zip"

echo "== javac"
find src "$OUT/gen" -name '*.java' > "$OUT/sources.txt"
# -source/-target 8 with the android.jar as bootclasspath is the non-Gradle
# equivalent of Android's core library, and keeps d8 happy.
"$JAVAC" -source 8 -target 8 -nowarn -bootclasspath "$ANDROID_JAR" \
  -d "$OUT/classes" @"$OUT/sources.txt"

echo "== d8"
# shellcheck disable=SC2046
"$JAVA" -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 \
  --release --min-api "$MIN_SDK" --lib "$ANDROID_JAR" \
  --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')

echo "== package"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
cp "$OUT/dex/classes.dex" "$OUT/classes.dex"
(cd "$OUT" && "$JARTOOL" uf unsigned.apk classes.dex)
"$ZIPALIGN" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

echo "== sign"
KS=release.keystore
STOREPASS=anomalywatch
if [ ! -f "$KS" ]; then
  "$KEYTOOL" -genkeypair -keystore "$KS" -alias anomalywatch \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$STOREPASS" -keypass "$STOREPASS" \
    -dname "CN=Anomaly Watch, O=Anomaly Watch, C=US"
fi

mkdir -p ../dist
APK="../dist/anomaly-watch-$VERSION_NAME.apk"
"$JAVA" -jar "$BT/lib/apksigner.jar" sign \
  --ks "$KS" --ks-pass "pass:$STOREPASS" --key-pass "pass:$STOREPASS" \
  --out "$APK" "$OUT/aligned.apk"

echo "== verify"
"$JAVA" -jar "$BT/lib/apksigner.jar" verify --print-certs "$APK" | head -4
ls -lh "$APK"
