package com.manifestsecurity.manifest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class QueryIntentInfo {
    private final List<String> actions;
    private final List<String> categories;
    private final List<IntentDataInfo> data;
    private final ManifestNode node;

    public QueryIntentInfo(List<String> actions, List<String> categories, List<IntentDataInfo> data, ManifestNode node) {
        this.actions = actions == null ? new ArrayList<String>() : new ArrayList<>(actions);
        this.categories = categories == null ? new ArrayList<String>() : new ArrayList<>(categories);
        this.data = data == null ? new ArrayList<IntentDataInfo>() : new ArrayList<>(data);
        this.node = node;
    }

    public List<String> getActions() {
        return Collections.unmodifiableList(actions);
    }

    public List<String> getCategories() {
        return Collections.unmodifiableList(categories);
    }

    public List<IntentDataInfo> getData() {
        return Collections.unmodifiableList(data);
    }

    public ManifestNode getNode() {
        return node;
    }

    public boolean isBroad() {
        if (!actions.isEmpty() && categories.isEmpty() && data.isEmpty()) {
            return true;
        }
        for (IntentDataInfo info : data) {
            if (info.getScheme().isEmpty() && info.getHost().isEmpty() && info.getMimeType().isEmpty()) {
                return true;
            }
        }
        return false;
    }
}
