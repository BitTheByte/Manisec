package com.manifestsecurity.manifest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ComponentInfo {
    private final ComponentType type;
    private final String name;
    private final String resolvedName;
    private final ManifestNode node;
    private final List<IntentFilterInfo> intentFilters;

    public ComponentInfo(ComponentType type,
                         String name,
                         String resolvedName,
                         ManifestNode node,
                         List<IntentFilterInfo> intentFilters) {
        this.type = type;
        this.name = name == null ? "" : name;
        this.resolvedName = resolvedName == null ? "" : resolvedName;
        this.node = node;
        this.intentFilters = intentFilters == null ? new ArrayList<IntentFilterInfo>() : new ArrayList<>(intentFilters);
    }

    public ComponentType getType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public String getResolvedName() {
        return resolvedName;
    }

    public ManifestNode getNode() {
        return node;
    }

    public List<IntentFilterInfo> getIntentFilters() {
        return Collections.unmodifiableList(intentFilters);
    }

    public String getAttribute(String name) {
        return node == null ? "" : node.getAttribute(name);
    }

    public boolean hasIntentFilter() {
        return intentFilters != null && !intentFilters.isEmpty();
    }
}
