package com.manifestsecurity.rules;

import com.manifestsecurity.manifest.ManifestModel;
import com.manifestsecurity.manifest.ManifestSource;
import com.manifestsecurity.manifest.PermissionInfo;
import com.manifestsecurity.util.PermissionCatalog;
import com.manifestsecurity.util.ResourceResolver;

import java.util.HashSet;
import java.util.Set;

public class RuleContext {
    private final ManifestModel model;
    private final ManifestSource source;
    private final ResourceResolver resourceResolver;
    private final Set<String> appDefinedPermissions;

    public RuleContext(ManifestModel model, ManifestSource source, ResourceResolver resourceResolver) {
        this.model = model;
        this.source = source;
        this.resourceResolver = resourceResolver;
        this.appDefinedPermissions = new HashSet<>();
        if (model != null && model.getCustomPermissions() != null) {
            for (PermissionInfo info : model.getCustomPermissions()) {
                if (info.getName() != null && !info.getName().isEmpty()) {
                    appDefinedPermissions.add(info.getName());
                }
            }
        }
    }

    public ManifestModel getModel() {
        return model;
    }

    public ManifestSource getSource() {
        return source;
    }

    public ResourceResolver getResourceResolver() {
        return resourceResolver;
    }

    public Set<String> getAppDefinedPermissions() {
        return appDefinedPermissions;
    }

    public boolean isKnownPermission(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (appDefinedPermissions.contains(name)) {
            return true;
        }
        return PermissionCatalog.FRAMEWORK_PERMISSIONS.contains(name);
    }
}
