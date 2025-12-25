package com.manifestsecurity.ui;

import com.manifestsecurity.model.ManifestFinding;
import com.manifestsecurity.model.ManifestScanResult;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;
import java.util.function.Consumer;

public class ManifestSecurityWindow extends JDialog {
    private final FindingsTableModel tableModel;
    private final JTable table;
    private final Consumer<ManifestFinding> onNavigate;

    public ManifestSecurityWindow(java.awt.Frame owner, ManifestScanResult result, Consumer<ManifestFinding> onNavigate) {
        super(owner, "Manisec", false);
        this.onNavigate = onNavigate;
        this.tableModel = new FindingsTableModel(result.getFindings());
        this.table = new JTable(tableModel);
        this.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        this.table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        JLabel header = new JLabel(buildHeader(result));
        JPanel top = new JPanel(new BorderLayout());
        top.add(header, BorderLayout.WEST);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton navigate = new JButton("Navigate");
        navigate.addActionListener(e -> navigateSelected());
        JButton close = new JButton("Close");
        close.addActionListener(e -> setVisible(false));
        actions.add(navigate);
        actions.add(close);

        setLayout(new BorderLayout());
        add(top, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(actions, BorderLayout.SOUTH);
        setSize(900, 520);
        setLocationRelativeTo(owner);
    }

    private String buildHeader(ManifestScanResult result) {
        String pkg = result.getPackageName();
        int count = result.getFindings().size();
        if (pkg == null || pkg.isEmpty()) {
            return "Findings: " + count;
        }
        return "Package: " + pkg + "   |   Findings: " + count;
    }

    private void navigateSelected() {
        int row = table.getSelectedRow();
        if (row < 0 || onNavigate == null) {
            return;
        }
        int modelRow = table.convertRowIndexToModel(row);
        ManifestFinding finding = tableModel.getFindingAt(modelRow);
        if (finding != null && finding.getClassName() != null && !finding.getClassName().isEmpty()) {
            onNavigate.accept(finding);
        }
    }

    public void showWindow() {
        SwingUtilities.invokeLater(() -> setVisible(true));
    }

    private static final class FindingsTableModel extends AbstractTableModel {
        private final String[] columns = {"Severity", "Category", "Component", "Detail", "Class"};
        private final List<ManifestFinding> findings;

        FindingsTableModel(List<ManifestFinding> findings) {
            this.findings = findings;
        }

        ManifestFinding getFindingAt(int row) {
            if (row < 0 || row >= findings.size()) {
                return null;
            }
            return findings.get(row);
        }

        @Override
        public int getRowCount() {
            return findings.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            ManifestFinding finding = findings.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return finding.getSeverity();
                case 1:
                    return finding.getCategory();
                case 2:
                    return finding.getComponent();
                case 3:
                    return finding.getDetail();
                case 4:
                    return finding.getClassName();
                default:
                    return "";
            }
        }
    }
}
