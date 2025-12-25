package com.manifestsecurity;

import com.manifestsecurity.model.ManifestFinding;
import com.manifestsecurity.model.ManifestScanResult;
import jadx.api.ICodeInfo;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.core.xmlgen.ResContainer;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

public final class ManifestSecurityScanner {
    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";

    private ManifestSecurityScanner() {
    }

    public static ManifestScanResult scan(JadxDecompiler decompiler) {
        String xml = loadManifestXml(decompiler);
        if (xml == null || xml.trim().isEmpty()) {
            return new ManifestScanResult("", new ArrayList<ManifestFinding>());
        }
        return parseManifest(xml);
    }

    private static String loadManifestXml(JadxDecompiler decompiler) {
        if (decompiler == null) {
            return null;
        }
        List<ResourceFile> resources = decompiler.getResources();
        if (resources == null) {
            return null;
        }
        for (ResourceFile res : resources) {
            if (res == null) {
                continue;
            }
            if (res.getType() == ResourceType.MANIFEST
                    || "AndroidManifest.xml".equalsIgnoreCase(res.getOriginalName())
                    || "AndroidManifest.xml".equalsIgnoreCase(res.getDeobfName())) {
                String text = loadResourceText(res);
                if (text != null && !text.trim().isEmpty()) {
                    return text;
                }
            }
        }
        return null;
    }

    private static String loadResourceText(ResourceFile res) {
        try {
            ResContainer container = res.loadContent();
            return extractText(container);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String extractText(ResContainer container) {
        if (container == null) {
            return null;
        }
        ICodeInfo text = container.getText();
        if (text != null) {
            return text.getCodeStr();
        }
        List<ResContainer> subs = container.getSubFiles();
        if (subs != null) {
            for (ResContainer sub : subs) {
                String out = extractText(sub);
                if (out != null) {
                    return out;
                }
            }
        }
        return null;
    }

    private static ManifestScanResult parseManifest(String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
            Element manifest = doc.getDocumentElement();
            String pkg = manifest != null ? manifest.getAttribute("package") : "";
            List<ManifestFinding> findings = new ArrayList<>();

            if (manifest != null) {
                String sharedUserId = attr(manifest, "sharedUserId");
                if (!sharedUserId.isEmpty()) {
                    findings.add(new ManifestFinding("MEDIUM", "Shared User ID",
                            "Manifest", "sharedUserId=" + sharedUserId, null));
                }
            }

            NodeList apps = doc.getElementsByTagName("application");
            if (apps != null && apps.getLength() > 0) {
                Element app = (Element) apps.item(0);
                String debuggable = attr(app, "debuggable");
                if ("true".equalsIgnoreCase(debuggable)) {
                    findings.add(new ManifestFinding("HIGH", "Debuggable App",
                            "application", "android:debuggable=true", null));
                }
                String allowBackup = attr(app, "allowBackup");
                if ("true".equalsIgnoreCase(allowBackup)) {
                    findings.add(new ManifestFinding("MEDIUM", "Backup Enabled",
                            "application", "android:allowBackup=true", null));
                }
                String cleartext = attr(app, "usesCleartextTraffic");
                if ("true".equalsIgnoreCase(cleartext)) {
                    findings.add(new ManifestFinding("MEDIUM", "Cleartext Traffic",
                            "application", "android:usesCleartextTraffic=true", null));
                }
                scanComponents(app, pkg, findings);
            }

            return new ManifestScanResult(pkg, findings);
        } catch (Exception e) {
            return new ManifestScanResult("", new ArrayList<ManifestFinding>());
        }
    }

    private static void scanComponents(Element app, String pkg, List<ManifestFinding> findings) {
        scanComponent(app, "activity", pkg, findings);
        scanComponent(app, "activity-alias", pkg, findings);
        scanComponent(app, "service", pkg, findings);
        scanComponent(app, "receiver", pkg, findings);
        scanComponent(app, "provider", pkg, findings);
    }

    private static void scanComponent(Element app, String tag, String pkg, List<ManifestFinding> findings) {
        NodeList nodes = app.getElementsByTagName(tag);
        if (nodes == null) {
            return;
        }
        for (int i = 0; i < nodes.getLength(); i++) {
            Element el = (Element) nodes.item(i);
            String name = attr(el, "name");
            if (name.isEmpty()) {
                continue;
            }
            String className = resolveClassName(pkg, name);
            String exportedAttr = attr(el, "exported");
            boolean hasIntentFilter = el.getElementsByTagName("intent-filter").getLength() > 0;
            Boolean exported = null;
            if (!exportedAttr.isEmpty()) {
                exported = Boolean.valueOf(exportedAttr);
            }
            boolean isExported = exported != null ? exported : hasIntentFilter;
            String permission = attr(el, "permission");

            if (isExported) {
                findings.add(new ManifestFinding("MEDIUM", "Exported Component",
                        tag + ": " + name,
                        exportedDetail(exportedAttr, hasIntentFilter), className));
                if (permission.isEmpty()) {
                    findings.add(new ManifestFinding("HIGH", "Exported Without Permission",
                            tag + ": " + name,
                            "No android:permission declared", className));
                }
            }
            if (!permission.isEmpty()) {
                findings.add(new ManifestFinding("INFO", "Component Permission",
                        tag + ": " + name, "android:permission=" + permission, className));
            }
        }
    }

    private static String exportedDetail(String exportedAttr, boolean hasIntentFilter) {
        if (!exportedAttr.isEmpty()) {
            return "android:exported=" + exportedAttr;
        }
        if (hasIntentFilter) {
            return "Exported via intent-filter (default)";
        }
        return "Exported";
    }

    private static String resolveClassName(String pkg, String rawName) {
        String name = rawName.trim();
        if (name.startsWith(".")) {
            return pkg + name;
        }
        if (name.contains(".")) {
            return name;
        }
        if (pkg == null || pkg.isEmpty()) {
            return name;
        }
        return pkg + "." + name;
    }

    private static String attr(Element el, String name) {
        if (el == null) {
            return "";
        }
        String val = "";
        try {
            val = el.getAttributeNS(ANDROID_NS, name);
        } catch (Exception ignored) {
        }
        if (val == null || val.isEmpty()) {
            val = el.getAttribute("android:" + name);
        }
        if (val == null || val.isEmpty()) {
            val = el.getAttribute(name);
        }
        return val == null ? "" : val.trim();
    }
}
