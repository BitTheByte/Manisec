package com.manifestsecurity.report;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class JsonExporter {
    public String export(ReportModel report) {
        StringBuilder sb = new StringBuilder(8192);
        appendReport(sb, report);
        return sb.toString();
    }

    public void exportToFile(File file, ReportModel report) throws Exception {
        if (file == null || report == null) {
            return;
        }
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
            writer.write(export(report));
        }
    }

    private void appendReport(StringBuilder sb, ReportModel report) {
        sb.append("{");
        appendField(sb, "packageName", report.getPackageName());
        sb.append(",\"findings\":[");
        List<Finding> findings = report.getFindings();
        for (int i = 0; i < findings.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            appendFinding(sb, findings.get(i));
        }
        sb.append("]}");
    }

    private void appendFinding(StringBuilder sb, Finding finding) {
        sb.append('{');
        appendField(sb, "id", finding.getId());
        sb.append(',');
        appendField(sb, "title", finding.getTitle());
        sb.append(',');
        appendField(sb, "confidence", finding.getConfidence().name());
        sb.append(',');
        appendField(sb, "category", finding.getCategory());
        sb.append(',');
        appendField(sb, "description", finding.getDescription());
        sb.append(',');
        appendField(sb, "impact", finding.getImpact());
        sb.append(',');
        appendField(sb, "recommendation", finding.getRecommendation());
        sb.append(",\"references\":[");
        List<Reference> references = finding.getReferences();
        for (int i = 0; i < references.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            appendReference(sb, references.get(i));
        }
        sb.append("]");
        sb.append(",\"evidence\":[");
        List<EvidenceItem> evidence = finding.getEvidence();
        for (int i = 0; i < evidence.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            appendEvidence(sb, evidence.get(i));
        }
        sb.append("]");
        sb.append('}');
    }

    private void appendReference(StringBuilder sb, Reference reference) {
        sb.append('{');
        appendField(sb, "label", reference.getLabel());
        sb.append(',');
        appendField(sb, "uri", reference.getUri());
        sb.append('}');
    }

    private void appendEvidence(StringBuilder sb, EvidenceItem evidence) {
        sb.append('{');
        appendField(sb, "componentType", evidence.getComponentType());
        sb.append(',');
        appendField(sb, "componentName", evidence.getComponentName());
        sb.append(',');
        appendField(sb, "manifestPath", evidence.getManifestPath());
        sb.append(',');
        appendField(sb, "attribute", evidence.getAttribute());
        sb.append(',');
        appendField(sb, "value", evidence.getValue());
        sb.append(',');
        appendField(sb, "snippet", evidence.getSnippet());
        Location loc = evidence.getLocation();
        sb.append(",\"location\":");
        if (loc == null) {
            sb.append("null");
        } else {
            sb.append('{');
            appendNumberField(sb, "line", loc.getLine());
            sb.append(',');
            appendNumberField(sb, "column", loc.getColumn());
            sb.append(',');
            appendNumberField(sb, "startOffset", loc.getStartOffset());
            sb.append(',');
            appendNumberField(sb, "endOffset", loc.getEndOffset());
            sb.append('}');
        }
        NavigationHint nav = evidence.getNavigationHint();
        sb.append(",\"navigation\":");
        if (nav == null) {
            sb.append("null");
        } else {
            sb.append('{');
            appendField(sb, "resourceName", nav.getResourceName());
            sb.append(',');
            appendField(sb, "manifestPath", nav.getManifestPath());
            Location nloc = nav.getLocation();
            sb.append(",\"location\":");
            if (nloc == null) {
                sb.append("null");
            } else {
                sb.append('{');
                appendNumberField(sb, "line", nloc.getLine());
                sb.append(',');
                appendNumberField(sb, "column", nloc.getColumn());
                sb.append(',');
                appendNumberField(sb, "startOffset", nloc.getStartOffset());
                sb.append(',');
                appendNumberField(sb, "endOffset", nloc.getEndOffset());
                sb.append('}');
            }
            sb.append('}');
        }
        sb.append('}');
    }

    private void appendField(StringBuilder sb, String name, String value) {
        sb.append('"').append(escape(name)).append("\":");
        if (value == null) {
            sb.append("null");
        } else {
            sb.append('"').append(escape(value)).append('"');
        }
    }

    private void appendNumberField(StringBuilder sb, String name, int value) {
        sb.append('"').append(escape(name)).append("\":").append(value);
    }

    private String escape(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(input.length() + 16);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        String hex = Integer.toHexString(c);
                        out.append("\\u");
                        for (int j = hex.length(); j < 4; j++) {
                            out.append('0');
                        }
                        out.append(hex);
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
