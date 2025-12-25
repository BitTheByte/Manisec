package com.manifestsecurity.report;

public class NavigationHint {
    private final String resourceName;
    private final String manifestPath;
    private final Location location;

    public NavigationHint(String resourceName, String manifestPath, Location location) {
        this.resourceName = resourceName;
        this.manifestPath = manifestPath;
        this.location = location;
    }

    public String getResourceName() {
        return resourceName;
    }

    public String getManifestPath() {
        return manifestPath;
    }

    public Location getLocation() {
        return location;
    }
}
