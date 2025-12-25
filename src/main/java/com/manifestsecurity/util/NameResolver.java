package com.manifestsecurity.util;

public class NameResolver {
    private NameResolver() {
    }

    public static String resolveClassName(String pkg, String rawName) {
        if (rawName == null) {
            return "";
        }
        String name = rawName.trim();
        if (name.isEmpty()) {
            return "";
        }
        if (name.startsWith(".")) {
            return (pkg == null ? "" : pkg) + name;
        }
        if (name.contains(".")) {
            return name;
        }
        if (pkg == null || pkg.isEmpty()) {
            return name;
        }
        return pkg + "." + name;
    }
}
