package com.manifestsecurity.manifest;

import jadx.api.ICodeInfo;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.core.dex.nodes.RootNode;
import jadx.core.xmlgen.BinaryXMLParser;
import jadx.core.xmlgen.ResContainer;

import java.io.ByteArrayInputStream;
import java.util.List;

public class ManifestLoader {
    public ManifestSource load(JadxDecompiler decompiler) {
        if (decompiler == null) {
            return new ManifestSource("", null, null);
        }
        List<ResourceFile> resources = decompiler.getResources();
        if (resources == null) {
            return new ManifestSource("", null, null);
        }
        for (ResourceFile res : resources) {
            if (res == null) {
                continue;
            }
            if (!isManifestResource(res)) {
                continue;
            }
            ManifestSource source = loadFromResource(decompiler, res);
            if (source != null && source.getXml() != null && !source.getXml().trim().isEmpty()) {
                return source;
            }
        }
        return new ManifestSource("", null, null);
    }

    private boolean isManifestResource(ResourceFile res) {
        if (res.getType() == ResourceType.MANIFEST) {
            return true;
        }
        String name = res.getOriginalName();
        if (name != null && "AndroidManifest.xml".equalsIgnoreCase(name)) {
            return true;
        }
        String deobf = res.getDeobfName();
        return deobf != null && "AndroidManifest.xml".equalsIgnoreCase(deobf);
    }

    private ManifestSource loadFromResource(JadxDecompiler decompiler, ResourceFile res) {
        try {
            ResContainer container = res.loadContent();
            ICodeInfo info = extractText(container);
            if (info != null && info.getCodeStr() != null && !info.getCodeStr().trim().isEmpty()) {
                return new ManifestSource(info.getCodeStr(), res, info);
            }
            byte[] decoded = extractDecoded(container);
            if (decoded != null && decoded.length > 0) {
                RootNode root = decompiler.getRoot();
                if (root != null) {
                    BinaryXMLParser parser = new BinaryXMLParser(root);
                    ICodeInfo decodedText = parser.parse(new ByteArrayInputStream(decoded));
                    if (decodedText != null && decodedText.getCodeStr() != null) {
                        return new ManifestSource(decodedText.getCodeStr(), res, decodedText);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private ICodeInfo extractText(ResContainer container) {
        if (container == null) {
            return null;
        }
        ICodeInfo text = container.getText();
        if (text != null && text.getCodeStr() != null && !text.getCodeStr().trim().isEmpty()) {
            return text;
        }
        if (container.getSubFiles() != null) {
            for (ResContainer sub : container.getSubFiles()) {
                ICodeInfo out = extractText(sub);
                if (out != null && out.getCodeStr() != null && !out.getCodeStr().trim().isEmpty()) {
                    return out;
                }
            }
        }
        return null;
    }

    private byte[] extractDecoded(ResContainer container) {
        if (container == null) {
            return null;
        }
        byte[] data = container.getDecodedData();
        if (data != null && data.length > 0) {
            return data;
        }
        if (container.getSubFiles() != null) {
            for (ResContainer sub : container.getSubFiles()) {
                byte[] out = extractDecoded(sub);
                if (out != null && out.length > 0) {
                    return out;
                }
            }
        }
        return null;
    }
}
