package com.manifestsecurity.rules;

import com.manifestsecurity.manifest.ManifestModel;
import com.manifestsecurity.manifest.ManifestSource;
import com.manifestsecurity.report.EvidenceItem;
import com.manifestsecurity.report.Finding;
import com.manifestsecurity.report.ReportModel;
import com.manifestsecurity.report.Severity;
import com.manifestsecurity.util.ResourceResolver;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class RuleEngine {
    public ReportModel analyze(ManifestModel model, ManifestSource source, ResourceResolver resolver) {
        RuleContext context = new RuleContext(model, source, resolver);
        List<Finding> findings = new ArrayList<>();
        for (ManifestRule rule : RuleRegistry.allRules()) {
            findings.addAll(rule.evaluate(model, context));
        }
        List<Finding> grouped = groupFindings(findings);
        Collections.sort(grouped, findingComparator());
        String pkg = model == null ? "" : model.getPackageName();
        return new ReportModel(pkg, grouped, source);
    }

    private List<Finding> groupFindings(List<Finding> input) {
        Map<String, Group> groups = new LinkedHashMap<>();
        for (Finding finding : input) {
            if (finding == null) {
                continue;
            }
            String key = buildGroupKey(finding);
            Group group = groups.get(key);
            if (group == null) {
                group = new Group(finding);
                groups.put(key, group);
            }
            group.addEvidence(finding.getEvidence());
        }
        List<Finding> out = new ArrayList<>();
        for (Group group : groups.values()) {
            out.add(group.toFinding());
        }
        return out;
    }

    private String buildGroupKey(Finding finding) {
        StringBuilder sb = new StringBuilder();
        sb.append(finding.getId()).append('|');
        sb.append(finding.getTitle()).append('|');
        sb.append(finding.getSeverity()).append('|');
        sb.append(finding.getConfidence()).append('|');
        sb.append(safe(finding.getCategory())).append('|');
        sb.append(safe(finding.getDescription())).append('|');
        sb.append(safe(finding.getImpact())).append('|');
        sb.append(safe(finding.getRecommendation())).append('|');
        sb.append(buildReferencesKey(finding));
        return sb.toString();
    }

    private String buildReferencesKey(Finding finding) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < finding.getReferences().size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(safe(finding.getReferences().get(i).getLabel())).append('=')
                    .append(safe(finding.getReferences().get(i).getUri()));
        }
        return sb.toString();
    }

    private Comparator<Finding> findingComparator() {
        return new Comparator<Finding>() {
            @Override
            public int compare(Finding a, Finding b) {
                if (a == null && b == null) {
                    return 0;
                }
                if (a == null) {
                    return 1;
                }
                if (b == null) {
                    return -1;
                }
                int sev = compareSeverity(a.getSeverity(), b.getSeverity());
                if (sev != 0) {
                    return sev;
                }
                int cat = safe(a.getCategory()).compareToIgnoreCase(safe(b.getCategory()));
                if (cat != 0) {
                    return cat;
                }
                int id = safe(a.getId()).compareToIgnoreCase(safe(b.getId()));
                if (id != 0) {
                    return id;
                }
                String compA = firstComponent(a);
                String compB = firstComponent(b);
                return safe(compA).compareToIgnoreCase(safe(compB));
            }
        };
    }

    private int compareSeverity(Severity a, Severity b) {
        if (a == null && b == null) {
            return 0;
        }
        if (a == null) {
            return 1;
        }
        if (b == null) {
            return -1;
        }
        return Integer.compare(b.rank(), a.rank());
    }

    private String firstComponent(Finding finding) {
        if (finding.getEvidence().isEmpty()) {
            return "";
        }
        EvidenceItem item = finding.getEvidence().get(0);
        return item == null ? "" : item.getComponentName();
    }

    private String safe(String input) {
        return input == null ? "" : input;
    }

    private static final class Group {
        private final Finding base;
        private final List<EvidenceItem> evidence = new ArrayList<>();
        private final Map<String, EvidenceItem> evidenceKeys = new LinkedHashMap<>();

        private Group(Finding base) {
            this.base = base;
        }

        private void addEvidence(List<EvidenceItem> items) {
            if (items == null) {
                return;
            }
            for (EvidenceItem item : items) {
                if (item == null) {
                    continue;
                }
                String key = buildEvidenceKey(item);
                if (!evidenceKeys.containsKey(key)) {
                    evidenceKeys.put(key, item);
                    evidence.add(item);
                }
            }
        }

        private String buildEvidenceKey(EvidenceItem item) {
            StringBuilder sb = new StringBuilder();
            sb.append(safe(item.getComponentType())).append('|');
            sb.append(safe(item.getComponentName())).append('|');
            sb.append(safe(item.getManifestPath())).append('|');
            sb.append(safe(item.getAttribute())).append('|');
            sb.append(safe(item.getValue()));
            return sb.toString();
        }

        private Finding toFinding() {
            return new Finding(base.getId(), base.getTitle(), base.getSeverity(), base.getConfidence(),
                    base.getCategory(), base.getDescription(), base.getImpact(), base.getRecommendation(),
                    base.getReferences(), evidence);
        }

        private String safe(String input) {
            return input == null ? "" : input;
        }
    }
}
