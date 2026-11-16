# Keep all DroidPilot JSON models, WebSocket server, security components, and services
-keepattributes Signature,InnerClasses,EnclosingMethod,RuntimeVisibleAnnotations
-keep class com.mobilemcp.pro.model.** { *; }
-keep class com.mobilemcp.pro.security.** { *; }
-keep class com.mobilemcp.pro.server.** { *; }
-keep class com.mobilemcp.pro.service.** { *; }
-keep class com.mobilemcp.pro.MainActivity { *; }
-keep class com.mobilemcp.pro.databinding.** { *; }

# Keep WebSocket & Gson serialization classes
-keep class org.java_websocket.** { *; }
-keep class com.google.gson.** { *; }
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

-dontwarn org.slf4j.**
-dontwarn javax.naming.**
