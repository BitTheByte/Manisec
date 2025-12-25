package com.manifestsecurity.report;

public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO;

    public int rank() {
        switch (this) {
            case CRITICAL:
                return 5;
            case HIGH:
                return 4;
            case MEDIUM:
                return 3;
            case LOW:
                return 2;
            case INFO:
            default:
                return 1;
        }
    }
}
