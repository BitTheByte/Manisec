package com.manifestsecurity.report;

public enum Confidence {
    HIGH,
    MEDIUM,
    LOW;

    public int rank() {
        switch (this) {
            case HIGH:
                return 3;
            case MEDIUM:
                return 2;
            case LOW:
            default:
                return 1;
        }
    }
}
