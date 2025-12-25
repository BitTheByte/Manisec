package com.manifestsecurity.util;

import java.util.ArrayList;
import java.util.List;

public class TextLocator {
    private final String text;
    private final List<Integer> lineOffsets = new ArrayList<>();

    public TextLocator(String text) {
        this.text = text == null ? "" : text;
        buildOffsets();
    }

    private void buildOffsets() {
        lineOffsets.clear();
        lineOffsets.add(0);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\n') {
                lineOffsets.add(i + 1);
            }
        }
    }

    public int toOffset(int line, int column) {
        if (line <= 0 || column <= 0) {
            return -1;
        }
        if (line > lineOffsets.size()) {
            return -1;
        }
        int start = lineOffsets.get(line - 1);
        int offset = start + (column - 1);
        if (offset < 0 || offset > text.length()) {
            return -1;
        }
        return offset;
    }

    public String snippet(int offset, int radius) {
        if (offset < 0 || offset > text.length()) {
            return "";
        }
        int start = Math.max(0, offset - radius);
        int end = Math.min(text.length(), offset + radius);
        return text.substring(start, end).trim();
    }

    public String getText() {
        return text;
    }
}
