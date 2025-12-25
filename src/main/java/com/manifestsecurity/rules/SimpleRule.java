package com.manifestsecurity.rules;

import com.manifestsecurity.manifest.ManifestModel;
import com.manifestsecurity.report.Finding;

import java.util.Collections;
import java.util.List;

public class SimpleRule implements ManifestRule {
    public interface Evaluator {
        List<Finding> evaluate(ManifestModel model, RuleContext context, SimpleRule rule);
    }

    private final String id;
    private final String title;
    private final String category;
    private final Evaluator evaluator;

    public SimpleRule(String id, String title, String category, Evaluator evaluator) {
        this.id = id;
        this.title = title;
        this.category = category;
        this.evaluator = evaluator;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getTitle() {
        return title;
    }

    @Override
    public String getCategory() {
        return category;
    }

    @Override
    public List<Finding> evaluate(ManifestModel model, RuleContext context) {
        if (evaluator == null) {
            return Collections.emptyList();
        }
        return evaluator.evaluate(model, context, this);
    }
}
