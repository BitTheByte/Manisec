package com.manifestsecurity;

import com.manifestsecurity.report.ReportModel;
import com.manifestsecurity.ui.ManifestNavigator;
import com.manifestsecurity.ui.ManifestSecurityDialog;
import jadx.api.JadxDecompiler;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.JadxPluginInfoBuilder;
import jadx.api.plugins.gui.JadxGuiContext;

import javax.swing.JFrame;
import javax.swing.SwingWorker;
public class ManifestSecurityPlugin implements JadxPlugin {
    private final ManifestSecurityService service = new ManifestSecurityService();
    private JadxDecompiler decompiler;
    private JadxGuiContext guiContext;
    private ManifestSecurityDialog dialog;

    @Override
    public JadxPluginInfo getPluginInfo() {
        return JadxPluginInfoBuilder.pluginId("manisec")
                .name("Manisec")
                .description("Manifest security analysis with navigable findings")
                .build();
    }

    @Override
    public void init(JadxPluginContext context) {
        this.decompiler = context.getDecompiler();
        this.guiContext = context.getGuiContext();
        if (guiContext != null) {
            guiContext.addMenuAction("Manisec Report", this::openReport);
        }
    }

    private void openReport() {
        if (decompiler == null || guiContext == null) {
            return;
        }
        JFrame frame = guiContext.getMainFrame();
        SwingWorker<ReportModel, Void> worker = new SwingWorker<ReportModel, Void>() {
            @Override
            protected ReportModel doInBackground() {
                return service.analyze(decompiler);
            }

            @Override
            protected void done() {
                try {
                    ReportModel report = get();
                    if (dialog != null) {
                        dialog.setVisible(false);
                        dialog.dispose();
                    }
                    ManifestNavigator navigator = new ManifestNavigator(decompiler, guiContext, report.getManifestSource());
                    dialog = new ManifestSecurityDialog(frame, report, navigator);
                    dialog.showWindow();
                } catch (Exception ignored) {
                }
            }
        };
        worker.execute();
    }

}
