package com.manifestsecurity.ui;

import com.manifestsecurity.report.Location;

import javax.swing.JDialog;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.BorderLayout;
import java.awt.Frame;

public class ManifestPreviewDialog extends JDialog {
    private final JTextArea textArea;

    public ManifestPreviewDialog(Frame owner, String manifestText) {
        super(owner, "AndroidManifest.xml", false);
        this.textArea = new JTextArea(manifestText == null ? "" : manifestText);
        this.textArea.setEditable(false);
        this.textArea.setLineWrap(false);
        this.textArea.setCaretPosition(0);

        JScrollPane scroll = new JScrollPane(textArea);
        setLayout(new BorderLayout());
        add(scroll, BorderLayout.CENTER);
        setSize(900, 600);
        setLocationRelativeTo(owner);
    }

    public void showAt(Location location) {
        SwingUtilities.invokeLater(() -> {
            highlight(location);
            setVisible(true);
            toFront();
        });
    }

    private void highlight(Location location) {
        Highlighter highlighter = textArea.getHighlighter();
        highlighter.removeAllHighlights();
        if (location == null) {
            return;
        }
        int start = Math.max(0, location.getStartOffset());
        int end = location.getEndOffset();
        if (end <= start) {
            end = Math.min(textArea.getText().length(), start + 1);
        }
        try {
            highlighter.addHighlight(start, end, new DefaultHighlighter.DefaultHighlightPainter(textArea.getSelectionColor()));
            textArea.setCaretPosition(start);
        } catch (Exception ignored) {
        }
    }
}
