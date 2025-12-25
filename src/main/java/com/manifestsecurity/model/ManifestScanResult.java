package com.manifestsecurity.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ManifestScanResult {
    private final String packageName;
    private final List<ManifestFinding> findings;

    public ManifestScanResult(String packageName, List<ManifestFinding> findings) {
        this.packageName = packageName == null ? "" : packageName;
        if (findings == null) {
            this.findings = new ArrayList<>();
        } else {
            this.findings = new ArrayList<>(findings);
        }
    }

    public String getPackageName() {
        return packageName;
    }

    public List<ManifestFinding> getFindings() {
        return Collections.unmodifiableList(findings);
    }
}
