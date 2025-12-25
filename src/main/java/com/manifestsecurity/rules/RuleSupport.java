package com.manifestsecurity.rules;

import com.manifestsecurity.manifest.ComponentInfo;
import com.manifestsecurity.manifest.ManifestNode;
import com.manifestsecurity.manifest.ManifestSource;
import com.manifestsecurity.report.Confidence;
import com.manifestsecurity.report.EvidenceItem;
import com.manifestsecurity.report.Finding;
import com.manifestsecurity.report.Location;
import com.manifestsecurity.report.NavigationHint;
import com.manifestsecurity.report.Reference;
import com.manifestsecurity.report.Severity;
import com.manifestsecurity.util.TextLocator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class RuleSupport {
    private RuleSupport() {
    }

    public static Finding buildFinding(SimpleRule rule,
                                       Severity severity,
                                       Confidence confidence,
                                       String description,
                                       String impact,
                                       String recommendation,
                                       List<Reference> references,
                                       List<EvidenceItem> evidence) {
        return new Finding(rule.getId(), rule.getTitle(), severity, confidence, rule.getCategory(),
                description, impact, recommendation, references, evidence);
    }

    public static EvidenceItem evidenceForComponent(ComponentInfo component,
                                                    ManifestSource source,
                                                    String attribute,
                                                    String value,
                                                    String snippet) {
        if (component == null) {
            return new EvidenceItem("", "", "", attribute, value, snippet, null, null);
        }
        ManifestNode node = component.getNode();
        return evidenceForNode(component.getType().name().toLowerCase(),
                component.getResolvedName().isEmpty() ? component.getName() : component.getResolvedName(),
                node, source, attribute, value, snippet);
    }

    public static EvidenceItem evidenceForNode(String componentType,
                                               String componentName,
                                               ManifestNode node,
                                               ManifestSource source,
                                               String attribute,
                                               String value,
                                               String snippet) {
        String path = node == null ? "" : node.buildPath();
        Location location = null;
        String safeSnippet = snippet == null ? "" : snippet;
        if (node != null && source != null) {
            TextLocator locator = source.getTextLocator();
            int offset = locator.toOffset(node.getLine(), node.getColumn());
            if (offset >= 0) {
                int end = Math.min(locator.getText().length(), offset + 80);
                location = new Location(node.getLine(), node.getColumn(), offset, end);
                if (safeSnippet.isEmpty()) {
                    safeSnippet = locator.snippet(offset, 120);
                }
            }
        }
        NavigationHint nav = new NavigationHint(source == null ? "" : source.getResourceName(), path, location);
        return new EvidenceItem(componentType, componentName, path, attribute, value, safeSnippet, location, nav);
    }

    public static List<EvidenceItem> evidenceList(EvidenceItem... items) {
        if (items == null || items.length == 0) {
            return Collections.emptyList();
        }
        List<EvidenceItem> list = new ArrayList<>();
        for (EvidenceItem item : items) {
            if (item != null) {
                list.add(item);
            }
        }
        return list;
    }
}
