package com.manifestsecurity.ui;

import com.manifestsecurity.report.EvidenceItem;
import com.manifestsecurity.report.Finding;
import com.manifestsecurity.report.JsonExporter;
import com.manifestsecurity.report.Reference;
import com.manifestsecurity.report.ReportModel;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ManifestSecurityDialog extends JDialog {
    private final ReportModel report;
    private final ManifestNavigator navigator;
    private final JComboBox<String> categoryFilter;
    private final JComboBox<String> componentFilter;
    private final JTextField searchField;
    private final JTree tree;
    private final FindingsDetailsPanel detailsPanel;
    private List<Finding> filtered;

    public ManifestSecurityDialog(Frame owner, ReportModel report, ManifestNavigator navigator) {
        super(owner, buildTitle(report), false);
        this.report = report;
        this.navigator = navigator;
        this.filtered = new ArrayList<>(report.getFindings());

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        this.categoryFilter = new JComboBox<>(buildCategories(report.getFindings()));
        this.componentFilter = new JComboBox<>(buildComponentTypes(report.getFindings()));
        this.searchField = new JTextField(20);
        JButton apply = new JButton("Apply");
        apply.addActionListener(e -> applyFilter());
        filterPanel.add(new JLabel("Category:"));
        filterPanel.add(categoryFilter);
        filterPanel.add(new JLabel("Component:"));
        filterPanel.add(componentFilter);
        filterPanel.add(new JLabel("Search:"));
        filterPanel.add(searchField);
        filterPanel.add(apply);

        this.tree = new JTree();
        this.tree.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.tree.addTreeSelectionListener(new TreeSelectionListener() {
            @Override
            public void valueChanged(TreeSelectionEvent e) {
                Object node = tree.getLastSelectedPathComponent();
                if (node instanceof DefaultMutableTreeNode) {
                    Object user = ((DefaultMutableTreeNode) node).getUserObject();
                    if (user instanceof TreeItem) {
                        detailsPanel.setFinding(((TreeItem) user).finding);
                    }
                }
            }
        });

        JScrollPane treeScroll = new JScrollPane(tree);
        this.detailsPanel = new FindingsDetailsPanel();
        this.detailsPanel.getEvidenceTable().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    navigateSelected();
                }
            }
        });

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, detailsPanel);
        split.setResizeWeight(0.35);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton navigate = new JButton("Navigate");
        navigate.addActionListener(e -> navigateSelected());
        JButton openManifest = new JButton("Open Manifest");
        openManifest.addActionListener(e -> {
            if (navigator != null) {
                navigator.openManifest();
            }
        });
        JButton exportJson = new JButton("Export JSON");
        exportJson.addActionListener(e -> exportJson());
        JButton close = new JButton("Close");
        close.addActionListener(e -> setVisible(false));
        actions.add(navigate);
        actions.add(openManifest);
        actions.add(exportJson);
        actions.add(close);

        setLayout(new BorderLayout());
        add(filterPanel, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(actions, BorderLayout.SOUTH);
        setSize(1100, 700);
        setLocationRelativeTo(owner);

        rebuildTree();
    }

    private static String buildTitle(ReportModel report) {
        if (report == null) {
            return "Manisec";
        }
        String pkg = report.getPackageName();
        if (pkg == null || pkg.trim().isEmpty()) {
            return "Manisec";
        }
        return "Manisec - " + pkg;
    }

    public void showWindow() {
        SwingUtilities.invokeLater(() -> setVisible(true));
    }

    private void applyFilter() {
        String category = (String) categoryFilter.getSelectedItem();
        String component = (String) componentFilter.getSelectedItem();
        String text = searchField.getText();
        filtered = new ArrayList<>();
        for (Finding finding : report.getFindings()) {
            if (!matchCategory(finding, category)) {
                continue;
            }
            if (!matchComponent(finding, component)) {
                continue;
            }
            if (!matchText(finding, text)) {
                continue;
            }
            filtered.add(finding);
        }
        rebuildTree();
    }

    private void rebuildTree() {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode(new TreeItem("Findings", null));
        Map<String, DefaultMutableTreeNode> categoryNodes = new HashMap<>();
        Map<String, DefaultMutableTreeNode> ruleNodes = new HashMap<>();
        for (Finding finding : filtered) {
            String category = safeCategory(finding.getCategory());
            DefaultMutableTreeNode categoryNode = categoryNodes.get(category);
            if (categoryNode == null) {
                categoryNode = new DefaultMutableTreeNode(new TreeItem(category, null));
                categoryNodes.put(category, categoryNode);
                root.add(categoryNode);
            }
            String ruleKey = category + "|" + finding.getId();
            DefaultMutableTreeNode ruleNode = ruleNodes.get(ruleKey);
            if (ruleNode == null) {
                String label = finding.getId() + " - " + finding.getTitle();
                ruleNode = new DefaultMutableTreeNode(new TreeItem(label, null));
                ruleNodes.put(ruleKey, ruleNode);
                categoryNode.add(ruleNode);
            }
            String leafLabel = finding.getTitle();
            ruleNode.add(new DefaultMutableTreeNode(new TreeItem(leafLabel, finding)));
        }
        tree.setModel(new DefaultTreeModel(root));
        for (int i = 0; i < tree.getRowCount(); i++) {
            tree.expandRow(i);
        }
    }

    private void navigateSelected() {
        EvidenceItem evidence = detailsPanel.getSelectedEvidence();
        if (evidence != null && navigator != null) {
            navigator.navigate(evidence);
        }
    }

    private void exportJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Manisec JSON");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON Files", "json"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".json")) {
            file = new File(file.getParentFile(), file.getName() + ".json");
        }
        try {
            new JsonExporter().exportToFile(file, report);
        } catch (Exception ignored) {
        }
    }

    private boolean matchCategory(Finding finding, String category) {
        if (category == null || "All".equals(category)) {
            return true;
        }
        return category.equals(safeCategory(finding.getCategory()));
    }

    private boolean matchComponent(Finding finding, String component) {
        if (component == null || "All".equals(component)) {
            return true;
        }
        for (EvidenceItem evidence : finding.getEvidence()) {
            if (component.equalsIgnoreCase(evidence.getComponentType())) {
                return true;
            }
        }
        return false;
    }

    private boolean matchText(Finding finding, String text) {
        if (text == null || text.trim().isEmpty()) {
            return true;
        }
        String needle = text.toLowerCase();
        if (safe(finding.getId()).toLowerCase().contains(needle)) {
            return true;
        }
        if (safe(finding.getTitle()).toLowerCase().contains(needle)) {
            return true;
        }
        if (safe(finding.getDescription()).toLowerCase().contains(needle)) {
            return true;
        }
        for (EvidenceItem evidence : finding.getEvidence()) {
            if (safe(evidence.getComponentName()).toLowerCase().contains(needle)) {
                return true;
            }
            if (safe(evidence.getManifestPath()).toLowerCase().contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private String[] buildCategories(List<Finding> findings) {
        Set<String> categories = new HashSet<>();
        categories.add("All");
        for (Finding finding : findings) {
            categories.add(safeCategory(finding.getCategory()));
        }
        return categories.toArray(new String[0]);
    }

    private String[] buildComponentTypes(List<Finding> findings) {
        Set<String> types = new HashSet<>();
        types.add("All");
        for (Finding finding : findings) {
            for (EvidenceItem evidence : finding.getEvidence()) {
                if (evidence.getComponentType() != null && !evidence.getComponentType().isEmpty()) {
                    types.add(evidence.getComponentType());
                }
            }
        }
        return types.toArray(new String[0]);
    }

    private String safe(String input) {
        return input == null ? "" : input;
    }

    private String safeCategory(String input) {
        if (input == null || input.trim().isEmpty()) {
            return "Other";
        }
        return input;
    }

    private static final class TreeItem {
        private final String label;
        private final Finding finding;

        private TreeItem(String label, Finding finding) {
            this.label = label;
            this.finding = finding;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static final class FindingsDetailsPanel extends JPanel {
        private final JLabel title;
        private final JLabel meta;
        private final JTextArea description;
        private final JTextArea impact;
        private final JTextArea recommendation;
        private final JTable evidenceTable;
        private final EvidenceTableModel evidenceModel;
        private final JTable referenceTable;
        private final ReferenceTableModel referenceModel;

        private FindingsDetailsPanel() {
            super(new BorderLayout());
            this.title = new JLabel("Select a finding");
            this.meta = new JLabel(" ");
            JPanel header = new JPanel(new BorderLayout());
            header.add(title, BorderLayout.NORTH);
            header.add(meta, BorderLayout.SOUTH);

            this.description = buildTextArea();
            this.impact = buildTextArea();
            this.recommendation = buildTextArea();

            this.evidenceModel = new EvidenceTableModel();
            this.evidenceTable = new JTable(evidenceModel);
            this.evidenceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            this.referenceModel = new ReferenceTableModel();
            this.referenceTable = new JTable(referenceModel);
            this.referenceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab("Description", new JScrollPane(description));
            tabs.addTab("Impact", new JScrollPane(impact));
            tabs.addTab("Recommendation", new JScrollPane(recommendation));
            tabs.addTab("Evidence", new JScrollPane(evidenceTable));
            tabs.addTab("References", new JScrollPane(referenceTable));

            add(header, BorderLayout.NORTH);
            add(tabs, BorderLayout.CENTER);
        }

        private JTextArea buildTextArea() {
            JTextArea area = new JTextArea();
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            return area;
        }

        public JTable getEvidenceTable() {
            return evidenceTable;
        }

        public void setFinding(Finding finding) {
            if (finding == null) {
                title.setText("Select a finding");
                meta.setText(" ");
                description.setText("");
                impact.setText("");
                recommendation.setText("");
                evidenceModel.setEvidence(new ArrayList<EvidenceItem>());
                referenceModel.setReferences(new ArrayList<Reference>());
                return;
            }
            title.setText(finding.getTitle());
            meta.setText("Rule: " + finding.getId()
                    + " | Confidence: " + finding.getConfidence() + " | Category: " + finding.getCategory());
            description.setText(safe(finding.getDescription()));
            impact.setText(safe(finding.getImpact()));
            recommendation.setText(safe(finding.getRecommendation()));
            evidenceModel.setEvidence(new ArrayList<>(finding.getEvidence()));
            referenceModel.setReferences(new ArrayList<>(finding.getReferences()));
        }

        public EvidenceItem getSelectedEvidence() {
            int row = evidenceTable.getSelectedRow();
            if (row < 0) {
                return null;
            }
            return evidenceModel.getEvidenceAt(row);
        }

        private String safe(String value) {
            return value == null ? "" : value;
        }
    }

    private static final class EvidenceTableModel extends AbstractTableModel {
        private final String[] columns = {"Type", "Component", "Attribute", "Value", "Path", "Snippet"};
        private List<EvidenceItem> evidence = new ArrayList<>();

        public void setEvidence(List<EvidenceItem> evidence) {
            this.evidence = evidence == null ? new ArrayList<EvidenceItem>() : evidence;
            fireTableDataChanged();
        }

        public EvidenceItem getEvidenceAt(int row) {
            if (row < 0 || row >= evidence.size()) {
                return null;
            }
            return evidence.get(row);
        }

        @Override
        public int getRowCount() {
            return evidence.size();
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
            EvidenceItem item = evidence.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return item.getComponentType();
                case 1:
                    return item.getComponentName();
                case 2:
                    return item.getAttribute();
                case 3:
                    return item.getValue();
                case 4:
                    return item.getManifestPath();
                case 5:
                    return item.getSnippet();
                default:
                    return "";
            }
        }
    }

    private static final class ReferenceTableModel extends AbstractTableModel {
        private final String[] columns = {"Label", "URI"};
        private List<Reference> references = new ArrayList<>();

        public void setReferences(List<Reference> references) {
            this.references = references == null ? new ArrayList<Reference>() : references;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return references.size();
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
            Reference ref = references.get(rowIndex);
            return columnIndex == 0 ? ref.getLabel() : ref.getUri();
        }
    }
}
