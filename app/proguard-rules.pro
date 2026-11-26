# Aura Mobile Defense - R8 Anti-Reverse-Engineering Hardening
-repackageclasses 'a.m.d'
-allowaccessmodification
-optimizationpasses 4
-renamesourcefileattribute SourceFile
-keepattributes Signature,InnerClasses,EnclosingMethod

# Strip verbose and debug logs in release builds while keeping error visibility
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
}

# Keep Room entities & DAOs
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-dontwarn androidx.room.paging.**

# Keep Firebase AI Logic / AppCheck / OkHttp reflection targets
-keep class com.google.firebase.ai.** { *; }
-keep class com.google.firebase.appcheck.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**

# SQLCipher: la biblioteca nativa y sus clases de enlace JNI se cargan por reflexión/JNI;
# R8 no puede ver esos usos y rompería la apertura de la base de datos en release.
-keep class net.zetetic.database.sqlcipher.** { *; }
-keep class net.zetetic.database.** { *; }
-dontwarn net.zetetic.**

# Tink (dependencia de Firebase/crypto) solo usa las anotaciones errorprone en tiempo
# de compilación; no existen en runtime y R8 falla si no se silencian.
-dontwarn com.google.errorprone.annotations.**
