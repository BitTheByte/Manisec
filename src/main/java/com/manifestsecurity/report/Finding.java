package com.manifestsecurity.report;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Finding {
    private final String id;
    private final String title;
    private final Severity severity;
    private final Confidence confidence;
    private final String category;
    private final String description;
    private final String impact;
    private final String recommendation;
    private final List<Reference> references;
    private final List<EvidenceItem> evidence;

    public Finding(String id,
                   String title,
                   Severity severity,
                   Confidence confidence,
                   String category,
                   String description,
                   String impact,
                   String recommendation,
                   List<Reference> references,
                   List<EvidenceItem> evidence) {
        this.id = id;
        this.title = title;
        this.severity = severity;
        this.confidence = confidence;
        this.category = category;
        this.description = description;
        this.impact = impact;
        this.recommendation = recommendation;
        this.references = references == null ? new ArrayList<Reference>() : new ArrayList<>(references);
        this.evidence = evidence == null ? new ArrayList<EvidenceItem>() : new ArrayList<>(evidence);
    }

    public String getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public Severity getSeverity() {
        return severity;
    }

    public Confidence getConfidence() {
        return confidence;
    }

    public String getCategory() {
        return category;
    }

    public String getDescription() {
        return description;
    }

    public String getImpact() {
        return impact;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public List<Reference> getReferences() {
        return Collections.unmodifiableList(references);
    }

    public List<EvidenceItem> getEvidence() {
        return Collections.unmodifiableList(evidence);
    }
}
