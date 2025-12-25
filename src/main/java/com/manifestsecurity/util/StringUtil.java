package com.manifestsecurity.util;

import java.util.Collection;

public class StringUtil {
    private StringUtil() {
    }

    public static String join(Collection<String> items, String sep) {
        if (items == null || items.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String item : items) {
            if (item == null || item.isEmpty()) {
                continue;
            }
            if (!first) {
                sb.append(sep);
            }
            sb.append(item);
            first = false;
        }
        return sb.toString();
    }

    public static boolean isTrue(String value) {
        return value != null && "true".equalsIgnoreCase(value.trim());
    }
}
