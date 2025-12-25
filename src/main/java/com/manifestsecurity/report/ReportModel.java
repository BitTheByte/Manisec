package com.manifestsecurity.report;

import com.manifestsecurity.manifest.ManifestSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ReportModel {
    private final String packageName;
    private final List<Finding> findings;
    private final ManifestSource manifestSource;

    public ReportModel(String packageName, List<Finding> findings, ManifestSource manifestSource) {
        this.packageName = packageName == null ? "" : packageName;
        this.findings = findings == null ? new ArrayList<Finding>() : new ArrayList<>(findings);
        this.manifestSource = manifestSource;
    }

    public String getPackageName() {
        return packageName;
    }

    public List<Finding> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    public ManifestSource getManifestSource() {
        return manifestSource;
    }
}
