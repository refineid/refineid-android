# A production build emits no application or dependency Logcat output.
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(java.lang.String, java.lang.String);
    public static int v(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int d(java.lang.String, java.lang.String);
    public static int d(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int i(java.lang.String, java.lang.String);
    public static int i(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int w(java.lang.String, java.lang.String);
    public static int w(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int w(java.lang.String, java.lang.Throwable);
    public static int e(java.lang.String, java.lang.String);
    public static int e(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int wtf(java.lang.String, java.lang.String);
    public static int wtf(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int wtf(java.lang.String, java.lang.Throwable);
    public static int println(int, java.lang.String, java.lang.String);
}

-assumevalues class android.util.Log {
    public static boolean isLoggable(java.lang.String, int) return false;
}

# Release dependencies must not bypass Logcat through console or JUL sinks.
-assumenosideeffects class java.io.PrintStream {
    public void print(...);
    public void println(...);
    public void write(...);
    public void flush();
    public java.io.PrintStream printf(...);
    public java.io.PrintStream format(...);
    public java.io.PrintStream append(...);
}

-assumenosideeffects class java.util.logging.Logger {
    public static java.util.logging.Logger getLogger(...);
    public void log(...);
    public void logp(...);
    public void logrb(...);
    public void severe(...);
    public void warning(...);
    public void info(...);
    public void config(...);
    public void fine(...);
    public void finer(...);
    public void finest(...);
    public void entering(...);
    public void exiting(...);
    public void throwing(...);
}

-assumevalues class java.util.logging.Logger {
    public boolean isLoggable(java.util.logging.Level) return false;
}

# Production also emits no Android performance trace sections.
-assumenosideeffects class android.os.Trace {
    public static boolean isEnabled();
    public static void beginSection(java.lang.String);
    public static void endSection();
    public static void beginAsyncSection(java.lang.String, int);
    public static void endAsyncSection(java.lang.String, int);
    public static void setCounter(java.lang.String, long);
}

-assumevalues class android.os.Trace {
    public static boolean isEnabled() return false;
}

# Rust invokes these synchronous callback names through JNI.
-keepclassmembernames class * implements fi.refineid.android.core.NativeBlockExchange {
    public byte[] exchangePublic(byte[]);
    public byte[] exchangeCredential(byte[]);
}
