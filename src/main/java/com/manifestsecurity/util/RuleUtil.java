package com.manifestsecurity.util;

import com.manifestsecurity.manifest.ComponentInfo;

public class RuleUtil {
    private RuleUtil() {
    }

    public static boolean hasExplicitExported(ComponentInfo component) {
        if (component == null) {
            return false;
        }
        String exported = component.getAttribute("android:exported");
        return exported != null && !exported.isEmpty();
    }

    public static boolean isExported(ComponentInfo component) {
        if (component == null) {
            return false;
        }
        String exported = component.getAttribute("android:exported");
        if (exported != null && !exported.isEmpty()) {
            return "true".equalsIgnoreCase(exported.trim());
        }
        return component.hasIntentFilter();
    }

    public static boolean hasPermission(ComponentInfo component) {
        if (component == null) {
            return false;
        }
        String perm = component.getAttribute("android:permission");
        return perm != null && !perm.isEmpty();
    }
}
