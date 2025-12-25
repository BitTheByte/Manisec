package com.manifestsecurity.manifest;

public class PermissionInfo {
    private final String name;
    private final String protectionLevel;
    private final ManifestNode node;

    public PermissionInfo(String name, String protectionLevel, ManifestNode node) {
        this.name = name == null ? "" : name;
        this.protectionLevel = protectionLevel == null ? "" : protectionLevel;
        this.node = node;
    }

    public String getName() {
        return name;
    }

    public String getProtectionLevel() {
        return protectionLevel;
    }

    public ManifestNode getNode() {
        return node;
    }
}
