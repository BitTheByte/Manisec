package com.manifestsecurity.util;

import jadx.api.ICodeInfo;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.core.xmlgen.ResContainer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ResourceResolver {
    private final Map<String, ResourceFile> xmlResources = new HashMap<>();

    public ResourceResolver(JadxDecompiler decompiler) {
        if (decompiler != null) {
            index(decompiler.getResources());
        }
    }

    private void index(List<ResourceFile> resources) {
        if (resources == null) {
            return;
        }
        for (ResourceFile res : resources) {
            if (res == null || res.getType() != ResourceType.XML) {
                continue;
            }
            String name = res.getOriginalName();
            if (name == null || name.isEmpty()) {
                name = res.getDeobfName();
            }
            if (name == null) {
                continue;
            }
            String simple = extractXmlSimpleName(name);
            if (simple != null && !simple.isEmpty()) {
                xmlResources.put(simple, res);
            }
        }
    }

    public String loadXmlByName(String xmlName) {
        if (xmlName == null) {
            return null;
        }
        ResourceFile res = xmlResources.get(xmlName);
        if (res == null) {
            return null;
        }
        try {
            ResContainer container = res.loadContent();
            ICodeInfo text = container == null ? null : container.getText();
            if (text != null) {
                return text.getCodeStr();
            }
            if (container != null && container.getSubFiles() != null) {
                for (ResContainer sub : container.getSubFiles()) {
                    if (sub.getText() != null) {
                        return sub.getText().getCodeStr();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String extractXmlSimpleName(String name) {
        String lower = name.replace('\\', '/');
        if (!lower.endsWith(".xml")) {
            return null;
        }
        int lastSlash = lower.lastIndexOf('/');
        String file = lastSlash >= 0 ? lower.substring(lastSlash + 1) : lower;
        if (file.endsWith(".xml")) {
            file = file.substring(0, file.length() - 4);
        }
        return file;
    }
}
