package com.manifestsecurity.manifest;

public class UsesSdkInfo {
    private final String minSdkVersion;
    private final String targetSdkVersion;
    private final String maxSdkVersion;
    private final ManifestNode node;

    public UsesSdkInfo(String minSdkVersion, String targetSdkVersion, String maxSdkVersion, ManifestNode node) {
        this.minSdkVersion = minSdkVersion == null ? "" : minSdkVersion;
        this.targetSdkVersion = targetSdkVersion == null ? "" : targetSdkVersion;
        this.maxSdkVersion = maxSdkVersion == null ? "" : maxSdkVersion;
        this.node = node;
    }

    public String getMinSdkVersion() {
        return minSdkVersion;
    }

    public String getTargetSdkVersion() {
        return targetSdkVersion;
    }

    public String getMaxSdkVersion() {
        return maxSdkVersion;
    }

    public ManifestNode getNode() {
        return node;
    }
}
