package com.manifestsecurity.manifest;

public class QueryPackageInfo {
    private final String name;
    private final ManifestNode node;

    public QueryPackageInfo(String name, ManifestNode node) {
        this.name = name == null ? "" : name;
        this.node = node;
    }

    public String getName() {
        return name;
    }

    public ManifestNode getNode() {
        return node;
    }
}
