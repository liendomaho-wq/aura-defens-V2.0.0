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
