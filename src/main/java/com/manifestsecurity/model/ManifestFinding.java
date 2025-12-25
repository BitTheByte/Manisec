package com.manifestsecurity.model;

public class ManifestFinding {
    private final String severity;
    private final String category;
    private final String component;
    private final String detail;
    private final String className;

    public ManifestFinding(String severity, String category, String component, String detail, String className) {
        this.severity = severity;
        this.category = category;
        this.component = component;
        this.detail = detail;
        this.className = className;
    }

    public String getSeverity() {
        return severity;
    }

    public String getCategory() {
        return category;
    }

    public String getComponent() {
        return component;
    }

    public String getDetail() {
        return detail;
    }

    public String getClassName() {
        return className;
    }
}
