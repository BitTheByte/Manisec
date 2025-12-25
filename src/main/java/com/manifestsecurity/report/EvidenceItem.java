package com.manifestsecurity.report;

public class EvidenceItem {
    private final String componentType;
    private final String componentName;
    private final String manifestPath;
    private final String attribute;
    private final String value;
    private final String snippet;
    private final Location location;
    private final NavigationHint navigationHint;

    public EvidenceItem(String componentType, String componentName, String manifestPath,
                        String attribute, String value, String snippet,
                        Location location, NavigationHint navigationHint) {
        this.componentType = componentType;
        this.componentName = componentName;
        this.manifestPath = manifestPath;
        this.attribute = attribute;
        this.value = value;
        this.snippet = snippet;
        this.location = location;
        this.navigationHint = navigationHint;
    }

    public String getComponentType() {
        return componentType;
    }

    public String getComponentName() {
        return componentName;
    }

    public String getManifestPath() {
        return manifestPath;
    }

    public String getAttribute() {
        return attribute;
    }

    public String getValue() {
        return value;
    }

    public String getSnippet() {
        return snippet;
    }

    public Location getLocation() {
        return location;
    }

    public NavigationHint getNavigationHint() {
        return navigationHint;
    }
}
