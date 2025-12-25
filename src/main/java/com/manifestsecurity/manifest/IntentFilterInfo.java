package com.manifestsecurity.manifest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class IntentFilterInfo {
    private final List<String> actions;
    private final List<String> categories;
    private final List<IntentDataInfo> data;
    private final boolean autoVerify;
    private final ManifestNode node;

    public IntentFilterInfo(List<String> actions,
                            List<String> categories,
                            List<IntentDataInfo> data,
                            boolean autoVerify,
                            ManifestNode node) {
        this.actions = actions == null ? new ArrayList<String>() : new ArrayList<>(actions);
        this.categories = categories == null ? new ArrayList<String>() : new ArrayList<>(categories);
        this.data = data == null ? new ArrayList<IntentDataInfo>() : new ArrayList<>(data);
        this.autoVerify = autoVerify;
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

    public boolean isAutoVerify() {
        return autoVerify;
    }

    public ManifestNode getNode() {
        return node;
    }

    public boolean isBrowsable() {
        for (String cat : categories) {
            if ("android.intent.category.BROWSABLE".equals(cat)) {
                return true;
            }
        }
        return false;
    }
}
