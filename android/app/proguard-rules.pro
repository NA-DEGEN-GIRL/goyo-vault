# The JNI bridge throws this class by name and calls its (String) constructor.
-keep class app.goyovault.GoyoException { <init>(java.lang.String); }
-keep class app.goyovault.Native { native <methods>; }
