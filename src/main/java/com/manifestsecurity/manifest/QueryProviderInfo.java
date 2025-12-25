package com.manifestsecurity.manifest;

public class QueryProviderInfo {
    private final String authority;
    private final ManifestNode node;

    public QueryProviderInfo(String authority, ManifestNode node) {
        this.authority = authority == null ? "" : authority;
        this.node = node;
    }

    public String getAuthority() {
        return authority;
    }

    public ManifestNode getNode() {
        return node;
    }
}
