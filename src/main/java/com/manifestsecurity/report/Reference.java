package com.manifestsecurity.report;

public class Reference {
    private final String label;
    private final String uri;

    public Reference(String label, String uri) {
        this.label = label;
        this.uri = uri;
    }

    public String getLabel() {
        return label;
    }

    public String getUri() {
        return uri;
    }
}
