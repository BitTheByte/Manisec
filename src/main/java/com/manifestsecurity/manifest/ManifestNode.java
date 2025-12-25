package com.manifestsecurity.manifest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ManifestNode {
    private final String name;
    private final Map<String, String> attributes;
    private final List<ManifestNode> children = new ArrayList<>();
    private ManifestNode parent;
    private int line;
    private int column;
    private int index;

    public ManifestNode(String name, Map<String, String> attributes) {
        this.name = name;
        this.attributes = attributes == null ? new LinkedHashMap<String, String>() : new LinkedHashMap<>(attributes);
    }

    public String getName() {
        return name;
    }

    public Map<String, String> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    public String getAttribute(String name) {
        if (name == null) {
            return "";
        }
        String val = attributes.get(name);
        if (val != null && !val.isEmpty()) {
            return val.trim();
        }
        if (name.startsWith("android:")) {
            String alt = name.substring("android:".length());
            val = attributes.get(alt);
            if (val != null && !val.isEmpty()) {
                return val.trim();
            }
        } else {
            String alt = "android:" + name;
            val = attributes.get(alt);
            if (val != null && !val.isEmpty()) {
                return val.trim();
            }
        }
        return "";
    }

    public void addChild(ManifestNode child) {
        if (child == null) {
            return;
        }
        child.parent = this;
        child.index = countChildIndex(child.name) + 1;
        children.add(child);
    }

    private int countChildIndex(String childName) {
        int count = 0;
        for (ManifestNode child : children) {
            if (childName.equals(child.name)) {
                count++;
            }
        }
        return count;
    }

    public List<ManifestNode> getChildren() {
        return Collections.unmodifiableList(children);
    }

    public ManifestNode getParent() {
        return parent;
    }

    public int getLine() {
        return line;
    }

    public void setLine(int line) {
        this.line = line;
    }

    public int getColumn() {
        return column;
    }

    public void setColumn(int column) {
        this.column = column;
    }

    public int getIndex() {
        return index;
    }

    public String buildPath() {
        if (parent == null) {
            return "/" + name;
        }
        String base = parent.buildPath() + "/" + name;
        String nameAttr = getAttribute("android:name");
        if (nameAttr != null && !nameAttr.isEmpty()) {
            return base + "[@android:name='" + nameAttr + "']";
        }
        if (index > 1) {
            return base + "[" + index + "]";
        }
        return base;
    }
}
