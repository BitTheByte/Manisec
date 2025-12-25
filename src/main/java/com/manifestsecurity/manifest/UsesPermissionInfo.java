package com.manifestsecurity.manifest;

public class UsesPermissionInfo {
    private final String name;
    private final String maxSdkVersion;
    private final String tagName;
    private final ManifestNode node;

    public UsesPermissionInfo(String name, String maxSdkVersion, String tagName, ManifestNode node) {
        this.name = name == null ? "" : name;
        this.maxSdkVersion = maxSdkVersion == null ? "" : maxSdkVersion;
        this.tagName = tagName == null ? "" : tagName;
        this.node = node;
    }

    public String getName() {
        return name;
    }

    public String getMaxSdkVersion() {
        return maxSdkVersion;
    }

    public String getTagName() {
        return tagName;
    }

    public ManifestNode getNode() {
        return node;
    }
}
