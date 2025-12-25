package com.manifestsecurity.report;

public class Location {
    private final int line;
    private final int column;
    private final int startOffset;
    private final int endOffset;

    public Location(int line, int column, int startOffset, int endOffset) {
        this.line = line;
        this.column = column;
        this.startOffset = startOffset;
        this.endOffset = endOffset;
    }

    public int getLine() {
        return line;
    }

    public int getColumn() {
        return column;
    }

    public int getStartOffset() {
        return startOffset;
    }

    public int getEndOffset() {
        return endOffset;
    }
}
