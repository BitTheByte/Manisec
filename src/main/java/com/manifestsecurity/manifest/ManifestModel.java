package com.manifestsecurity.manifest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class ManifestModel {
    private final String packageName;
    private final ManifestNode manifestNode;
    private final ManifestNode applicationNode;
    private final List<ComponentInfo> components;
    private final List<UsesPermissionInfo> usesPermissions;
    private final List<PermissionInfo> customPermissions;
    private final UsesSdkInfo usesSdk;
    private final QueryInfo queries;
    private final Map<String, String> manifestAttributes;
    private final Map<String, String> applicationAttributes;
    private final boolean profileable;

    public ManifestModel(String packageName,
                         ManifestNode manifestNode,
                         ManifestNode applicationNode,
                         List<ComponentInfo> components,
                         List<UsesPermissionInfo> usesPermissions,
                         List<PermissionInfo> customPermissions,
                         UsesSdkInfo usesSdk,
                         QueryInfo queries,
                         Map<String, String> manifestAttributes,
                         Map<String, String> applicationAttributes,
                         boolean profileable) {
        this.packageName = packageName == null ? "" : packageName;
        this.manifestNode = manifestNode;
        this.applicationNode = applicationNode;
        this.components = components == null ? new ArrayList<ComponentInfo>() : new ArrayList<>(components);
        this.usesPermissions = usesPermissions == null ? new ArrayList<UsesPermissionInfo>() : new ArrayList<>(usesPermissions);
        this.customPermissions = customPermissions == null ? new ArrayList<PermissionInfo>() : new ArrayList<>(customPermissions);
        this.usesSdk = usesSdk;
        this.queries = queries;
        this.manifestAttributes = manifestAttributes;
        this.applicationAttributes = applicationAttributes;
        this.profileable = profileable;
    }

    public String getPackageName() {
        return packageName;
    }

    public ManifestNode getManifestNode() {
        return manifestNode;
    }

    public ManifestNode getApplicationNode() {
        return applicationNode;
    }

    public List<ComponentInfo> getComponents() {
        return Collections.unmodifiableList(components);
    }

    public List<UsesPermissionInfo> getUsesPermissions() {
        return Collections.unmodifiableList(usesPermissions);
    }

    public List<PermissionInfo> getCustomPermissions() {
        return Collections.unmodifiableList(customPermissions);
    }

    public UsesSdkInfo getUsesSdk() {
        return usesSdk;
    }

    public QueryInfo getQueries() {
        return queries;
    }

    public String getManifestAttribute(String name) {
        if (manifestAttributes == null || name == null) {
            return "";
        }
        String val = manifestAttributes.get(name);
        if (val != null && !val.isEmpty()) {
            return val.trim();
        }
        if (!name.startsWith("android:")) {
            val = manifestAttributes.get("android:" + name);
            if (val != null && !val.isEmpty()) {
                return val.trim();
            }
        }
        return "";
    }

    public String getApplicationAttribute(String name) {
        if (applicationAttributes == null || name == null) {
            return "";
        }
        String val = applicationAttributes.get(name);
        if (val != null && !val.isEmpty()) {
            return val.trim();
        }
        if (!name.startsWith("android:")) {
            val = applicationAttributes.get("android:" + name);
            if (val != null && !val.isEmpty()) {
                return val.trim();
            }
        }
        return "";
    }

    public boolean isProfileable() {
        return profileable;
    }
}
