package com.manifestsecurity.manifest;

import com.manifestsecurity.util.NameResolver;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParserFactory;
import java.io.StringReader;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ManifestModelBuilder {
    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";

    public ManifestModel build(ManifestSource source) {
        if (source == null || source.getXml() == null || source.getXml().trim().isEmpty()) {
            return new ManifestModel("", null, null, new ArrayList<ComponentInfo>(),
                    new ArrayList<UsesPermissionInfo>(), new ArrayList<PermissionInfo>(),
                    null, new QueryInfo(null, null, null, null),
                    new LinkedHashMap<String, String>(), new LinkedHashMap<String, String>(), false);
        }
        ManifestNode root = parse(source.getXml());
        if (root == null) {
            return new ManifestModel("", null, null, new ArrayList<ComponentInfo>(),
                    new ArrayList<UsesPermissionInfo>(), new ArrayList<PermissionInfo>(),
                    null, new QueryInfo(null, null, null, null),
                    new LinkedHashMap<String, String>(), new LinkedHashMap<String, String>(), false);
        }
        String pkg = root.getAttribute("package");
        ManifestNode appNode = findFirstChild(root, "application");
        List<ComponentInfo> components = appNode == null ? new ArrayList<ComponentInfo>() : parseComponents(appNode, pkg);
        List<UsesPermissionInfo> usesPermissions = parseUsesPermissions(root);
        List<PermissionInfo> customPermissions = parseCustomPermissions(root);
        UsesSdkInfo usesSdk = parseUsesSdk(root);
        QueryInfo queries = parseQueries(root);
        Map<String, String> manifestAttrs = root.getAttributes();
        Map<String, String> appAttrs = appNode == null ? new LinkedHashMap<String, String>() : appNode.getAttributes();
        boolean profileable = isProfileable(appNode);
        return new ManifestModel(pkg, root, appNode, components, usesPermissions, customPermissions, usesSdk, queries,
                new LinkedHashMap<String, String>(manifestAttrs), new LinkedHashMap<String, String>(appAttrs), profileable);
    }

    private ManifestNode parse(String xml) {
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            try {
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            } catch (Exception ignored) {
            }
            ManifestHandler handler = new ManifestHandler();
            factory.newSAXParser().parse(new InputSource(new StringReader(xml)), handler);
            return handler.getRoot();
        } catch (Exception e) {
            return null;
        }
    }

    private ManifestNode findFirstChild(ManifestNode node, String name) {
        if (node == null) {
            return null;
        }
        for (ManifestNode child : node.getChildren()) {
            if (name.equals(child.getName())) {
                return child;
            }
        }
        return null;
    }

    private List<UsesPermissionInfo> parseUsesPermissions(ManifestNode root) {
        List<UsesPermissionInfo> list = new ArrayList<>();
        if (root == null) {
            return list;
        }
        for (ManifestNode child : root.getChildren()) {
            String name = child.getName();
            if ("uses-permission".equals(name) || "uses-permission-sdk-23".equals(name)) {
                String perm = child.getAttribute("android:name");
                String maxSdk = child.getAttribute("android:maxSdkVersion");
                if (!perm.isEmpty()) {
                    list.add(new UsesPermissionInfo(perm, maxSdk, name, child));
                }
            }
        }
        return list;
    }

    private List<PermissionInfo> parseCustomPermissions(ManifestNode root) {
        List<PermissionInfo> list = new ArrayList<>();
        if (root == null) {
            return list;
        }
        for (ManifestNode child : root.getChildren()) {
            if ("permission".equals(child.getName())) {
                String name = child.getAttribute("android:name");
                if (!name.isEmpty()) {
                    String prot = child.getAttribute("android:protectionLevel");
                    list.add(new PermissionInfo(name, prot, child));
                }
            }
        }
        return list;
    }

    private UsesSdkInfo parseUsesSdk(ManifestNode root) {
        if (root == null) {
            return null;
        }
        for (ManifestNode child : root.getChildren()) {
            if ("uses-sdk".equals(child.getName())) {
                return new UsesSdkInfo(child.getAttribute("android:minSdkVersion"),
                        child.getAttribute("android:targetSdkVersion"),
                        child.getAttribute("android:maxSdkVersion"), child);
            }
        }
        return null;
    }

    private QueryInfo parseQueries(ManifestNode root) {
        List<QueryPackageInfo> packages = new ArrayList<>();
        List<QueryIntentInfo> intents = new ArrayList<>();
        List<QueryProviderInfo> providers = new ArrayList<>();
        if (root == null) {
            return new QueryInfo(null, packages, intents, providers);
        }
        ManifestNode queries = findFirstChild(root, "queries");
        if (queries == null) {
            return new QueryInfo(queries, packages, intents, providers);
        }
        for (ManifestNode child : queries.getChildren()) {
            if ("package".equals(child.getName())) {
                String name = child.getAttribute("android:name");
                if (!name.isEmpty()) {
                    packages.add(new QueryPackageInfo(name, child));
                }
            } else if ("intent".equals(child.getName())) {
                intents.add(parseQueryIntent(child));
            } else if ("provider".equals(child.getName())) {
                String auth = child.getAttribute("android:authorities");
                if (!auth.isEmpty()) {
                    providers.add(new QueryProviderInfo(auth, child));
                }
            }
        }
        return new QueryInfo(queries, packages, intents, providers);
    }

    private QueryIntentInfo parseQueryIntent(ManifestNode node) {
        List<String> actions = new ArrayList<>();
        List<String> categories = new ArrayList<>();
        List<IntentDataInfo> data = new ArrayList<>();
        if (node != null) {
            for (ManifestNode child : node.getChildren()) {
                if ("action".equals(child.getName())) {
                    String name = child.getAttribute("android:name");
                    if (!name.isEmpty()) {
                        actions.add(name);
                    }
                } else if ("category".equals(child.getName())) {
                    String name = child.getAttribute("android:name");
                    if (!name.isEmpty()) {
                        categories.add(name);
                    }
                } else if ("data".equals(child.getName())) {
                    data.add(parseData(child));
                }
            }
        }
        return new QueryIntentInfo(actions, categories, data, node);
    }

    private List<ComponentInfo> parseComponents(ManifestNode appNode, String pkg) {
        List<ComponentInfo> list = new ArrayList<>();
        if (appNode == null) {
            return list;
        }
        for (ManifestNode child : appNode.getChildren()) {
            ComponentType type = mapComponentType(child.getName());
            if (type == null) {
                continue;
            }
            String name = child.getAttribute("android:name");
            if (name.isEmpty()) {
                continue;
            }
            String resolved = NameResolver.resolveClassName(pkg, name);
            List<IntentFilterInfo> filters = parseIntentFilters(child);
            list.add(new ComponentInfo(type, name, resolved, child, filters));
        }
        return list;
    }

    private ComponentType mapComponentType(String name) {
        if ("activity".equals(name)) {
            return ComponentType.ACTIVITY;
        }
        if ("activity-alias".equals(name)) {
            return ComponentType.ACTIVITY_ALIAS;
        }
        if ("service".equals(name)) {
            return ComponentType.SERVICE;
        }
        if ("receiver".equals(name)) {
            return ComponentType.RECEIVER;
        }
        if ("provider".equals(name)) {
            return ComponentType.PROVIDER;
        }
        return null;
    }

    private List<IntentFilterInfo> parseIntentFilters(ManifestNode node) {
        List<IntentFilterInfo> list = new ArrayList<>();
        if (node == null) {
            return list;
        }
        for (ManifestNode child : node.getChildren()) {
            if (!"intent-filter".equals(child.getName())) {
                continue;
            }
            List<String> actions = new ArrayList<>();
            List<String> categories = new ArrayList<>();
            List<IntentDataInfo> data = new ArrayList<>();
            for (ManifestNode intentChild : child.getChildren()) {
                if ("action".equals(intentChild.getName())) {
                    String name = intentChild.getAttribute("android:name");
                    if (!name.isEmpty()) {
                        actions.add(name);
                    }
                } else if ("category".equals(intentChild.getName())) {
                    String name = intentChild.getAttribute("android:name");
                    if (!name.isEmpty()) {
                        categories.add(name);
                    }
                } else if ("data".equals(intentChild.getName())) {
                    data.add(parseData(intentChild));
                }
            }
            boolean autoVerify = "true".equalsIgnoreCase(child.getAttribute("android:autoVerify"));
            list.add(new IntentFilterInfo(actions, categories, data, autoVerify, child));
        }
        return list;
    }

    private IntentDataInfo parseData(ManifestNode node) {
        if (node == null) {
            return new IntentDataInfo("", "", "", "", "", "", "");
        }
        return new IntentDataInfo(
                node.getAttribute("android:scheme"),
                node.getAttribute("android:host"),
                node.getAttribute("android:port"),
                node.getAttribute("android:path"),
                node.getAttribute("android:pathPrefix"),
                node.getAttribute("android:pathPattern"),
                node.getAttribute("android:mimeType")
        );
    }

    private boolean isProfileable(ManifestNode appNode) {
        if (appNode == null) {
            return false;
        }
        String attr = appNode.getAttribute("android:profileable");
        if ("true".equalsIgnoreCase(attr)) {
            return true;
        }
        for (ManifestNode child : appNode.getChildren()) {
            if ("profileable".equals(child.getName())) {
                String enabled = child.getAttribute("android:enabled");
                return enabled.isEmpty() || "true".equalsIgnoreCase(enabled);
            }
        }
        return false;
    }

    private static class ManifestHandler extends DefaultHandler {
        private final Deque<ManifestNode> stack = new ArrayDeque<>();
        private ManifestNode root;
        private Locator locator;

        @Override
        public void setDocumentLocator(Locator locator) {
            this.locator = locator;
        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            String name = localName != null && !localName.isEmpty() ? localName : qName;
            Map<String, String> attrs = new LinkedHashMap<>();
            if (attributes != null) {
                for (int i = 0; i < attributes.getLength(); i++) {
                    String attrName = attributes.getQName(i);
                    if (attrName == null || attrName.isEmpty()) {
                        attrName = attributes.getLocalName(i);
                    }
                    if (attrName == null || attrName.isEmpty()) {
                        continue;
                    }
                    if (ANDROID_NS.equals(attributes.getURI(i)) && !attrName.startsWith("android:")) {
                        attrName = "android:" + attrName;
                    }
                    attrs.put(attrName, attributes.getValue(i));
                }
            }
            ManifestNode node = new ManifestNode(name, attrs);
            if (locator != null) {
                node.setLine(locator.getLineNumber());
                node.setColumn(locator.getColumnNumber());
            }
            if (stack.isEmpty()) {
                root = node;
            } else {
                stack.peek().addChild(node);
            }
            stack.push(node);
        }

        @Override
        public void endElement(String uri, String localName, String qName) throws SAXException {
            if (!stack.isEmpty()) {
                stack.pop();
            }
        }

        public ManifestNode getRoot() {
            return root;
        }
    }
}
