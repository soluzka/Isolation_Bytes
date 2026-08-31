# Build the Android APK
#
# Prerequisites:
#   - Android Studio or Android SDK + JDK 17
#   - Gradle 8.5+ (or use the wrapper: ./gradlew)
#
# From the android/ directory:
#
#   Windows:  gradlew.bat assembleDebug
#   Linux:    ./gradlew assembleDebug
#
# Output APK:
#   android/app/build/outputs/apk/debug/app-debug.apk
#
# For a release build (needs a keystore):
#   1. Create a keystore:
#      keytool -genkey -v -keystore release.keystore -alias antivirus \
#        -keyalg RSA -keysize 2048 -validity 10000
#   2. Add to android/gradle.properties:
#      android.injected.signing.store.file=release.keystore
#      android.injected.signing.store.password=<password>
#      android.injected.signing.key.alias=antivirus
#      android.injected.signing.key.password=<password>
#   3. Build:
#      gradlew.bat assembleRelease
#
# The app connects to your cloud server. Set the server URL in
# Settings after installing the APK.
