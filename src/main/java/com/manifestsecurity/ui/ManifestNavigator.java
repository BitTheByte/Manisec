package com.manifestsecurity.ui;

import com.manifestsecurity.manifest.ManifestSource;
import com.manifestsecurity.report.EvidenceItem;
import com.manifestsecurity.report.Location;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.metadata.ICodeNodeRef;
import jadx.api.plugins.gui.JadxGuiContext;
import jadx.gui.treemodel.JResource;

import javax.swing.JFrame;

public class ManifestNavigator {
    private final JadxDecompiler decompiler;
    private final JadxGuiContext guiContext;
    private final ManifestSource source;
    private ManifestPreviewDialog previewDialog;

    public ManifestNavigator(JadxDecompiler decompiler, JadxGuiContext guiContext, ManifestSource source) {
        this.decompiler = decompiler;
        this.guiContext = guiContext;
        this.source = source;
    }

    public void navigate(EvidenceItem evidence) {
        if (evidence == null) {
            return;
        }
        if (openClassIfAvailable(evidence.getComponentName())) {
            return;
        }
        openManifest(evidence);
    }

    public void openManifest(EvidenceItem evidence) {
        openManifestInJadx();
        Location location = evidence == null ? null : evidence.getLocation();
        openPreview(location);
    }

    public void openManifest() {
        openManifestInJadx();
        openPreview(null);
    }

    private boolean openClassIfAvailable(String className) {
        if (className == null || className.trim().isEmpty() || decompiler == null || guiContext == null) {
            return false;
        }
        JavaClass javaClass = decompiler.searchJavaClassByOrigFullName(className);
        if (javaClass == null) {
            javaClass = decompiler.searchJavaClassByAliasFullName(className);
        }
        if (javaClass == null) {
            return false;
        }
        ICodeNodeRef ref = javaClass.getCodeNodeRef();
        if (ref != null) {
            guiContext.uiRun(() -> guiContext.open(ref));
            return true;
        }
        return false;
    }

    private void openManifestInJadx() {
        if (guiContext == null || source == null || source.getResourceFile() == null) {
            return;
        }
        String name = source.getResourceName();
        JResource res = new JResource(source.getResourceFile(), name, JResource.JResType.FILE);
        ICodeNodeRef ref = res.getCodeNodeRef();
        if (ref != null) {
            guiContext.uiRun(() -> guiContext.open(ref));
        }
    }

    private void openPreview(Location location) {
        if (source == null) {
            return;
        }
        JFrame frame = guiContext == null ? null : guiContext.getMainFrame();
        if (previewDialog == null) {
            previewDialog = new ManifestPreviewDialog(frame, source.getXml());
        }
        previewDialog.showAt(location);
    }
}
