package com.manifestsecurity.rules;

import com.manifestsecurity.manifest.ManifestModel;
import com.manifestsecurity.report.Finding;

import java.util.List;

public interface ManifestRule {
    String getId();

    String getTitle();

    String getCategory();

    List<Finding> evaluate(ManifestModel model, RuleContext context);
}
