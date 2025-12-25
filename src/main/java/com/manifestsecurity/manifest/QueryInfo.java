package com.manifestsecurity.manifest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class QueryInfo {
    private final ManifestNode node;
    private final List<QueryPackageInfo> packages;
    private final List<QueryIntentInfo> intents;
    private final List<QueryProviderInfo> providers;

    public QueryInfo(ManifestNode node, List<QueryPackageInfo> packages, List<QueryIntentInfo> intents, List<QueryProviderInfo> providers) {
        this.node = node;
        this.packages = packages == null ? new ArrayList<QueryPackageInfo>() : new ArrayList<>(packages);
        this.intents = intents == null ? new ArrayList<QueryIntentInfo>() : new ArrayList<>(intents);
        this.providers = providers == null ? new ArrayList<QueryProviderInfo>() : new ArrayList<>(providers);
    }

    public ManifestNode getNode() {
        return node;
    }

    public List<QueryPackageInfo> getPackages() {
        return Collections.unmodifiableList(packages);
    }

    public List<QueryIntentInfo> getIntents() {
        return Collections.unmodifiableList(intents);
    }

    public List<QueryProviderInfo> getProviders() {
        return Collections.unmodifiableList(providers);
    }
}
