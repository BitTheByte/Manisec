package com.manifestsecurity;

import com.manifestsecurity.manifest.ManifestLoader;
import com.manifestsecurity.manifest.ManifestModel;
import com.manifestsecurity.manifest.ManifestModelBuilder;
import com.manifestsecurity.manifest.ManifestSource;
import com.manifestsecurity.report.ReportModel;
import com.manifestsecurity.rules.RuleEngine;
import com.manifestsecurity.util.ResourceResolver;
import jadx.api.JadxDecompiler;

public class ManifestSecurityService {
    private final ManifestLoader loader = new ManifestLoader();
    private final ManifestModelBuilder modelBuilder = new ManifestModelBuilder();
    private final RuleEngine engine = new RuleEngine();

    private String lastManifestHash;
    private ReportModel lastReport;

    public synchronized ReportModel analyze(JadxDecompiler decompiler) {
        ManifestSource source = loader.load(decompiler);
        String xml = source == null ? "" : source.getXml();
        String hash = xml == null ? "" : Integer.toString(xml.hashCode());
        if (lastReport != null && hash.equals(lastManifestHash)) {
            return lastReport;
        }
        ManifestModel model = modelBuilder.build(source);
        ResourceResolver resolver = new ResourceResolver(decompiler);
        ReportModel report = engine.analyze(model, source, resolver);
        lastManifestHash = hash;
        lastReport = report;
        return report;
    }
}
