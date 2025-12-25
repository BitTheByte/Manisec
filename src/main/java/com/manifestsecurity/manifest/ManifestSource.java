package com.manifestsecurity.manifest;

import com.manifestsecurity.util.TextLocator;
import jadx.api.ICodeInfo;
import jadx.api.ResourceFile;

public class ManifestSource {
    private final String xml;
    private final ResourceFile resourceFile;
    private final ICodeInfo codeInfo;
    private final TextLocator textLocator;

    public ManifestSource(String xml, ResourceFile resourceFile, ICodeInfo codeInfo) {
        this.xml = xml == null ? "" : xml;
        this.resourceFile = resourceFile;
        this.codeInfo = codeInfo;
        this.textLocator = new TextLocator(this.xml);
    }

    public String getXml() {
        return xml;
    }

    public ResourceFile getResourceFile() {
        return resourceFile;
    }

    public ICodeInfo getCodeInfo() {
        return codeInfo;
    }

    public TextLocator getTextLocator() {
        return textLocator;
    }

    public String getResourceName() {
        if (resourceFile == null) {
            return "AndroidManifest.xml";
        }
        String name = resourceFile.getOriginalName();
        if (name == null || name.trim().isEmpty()) {
            name = resourceFile.getDeobfName();
        }
        return name == null || name.trim().isEmpty() ? "AndroidManifest.xml" : name;
    }
}
