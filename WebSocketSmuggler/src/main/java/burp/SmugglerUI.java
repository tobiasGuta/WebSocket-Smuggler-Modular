package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class SmugglerUI implements AttackEngine.AttackListener {

    private static final Color ACCENT = new Color(0xFF, 0x66, 0x33);
    private static final Color SMUGGLING_BG = new Color(255, 205, 210);
    private static final Color SMUGGLING_FG = new Color(183, 28, 28);
    private static final Color SAFE_BG = new Color(200, 230, 201);
    private static final Color SAFE_FG = new Color(27, 94, 32);
    private static final Color WARNING_BG = new Color(255, 249, 196);
    private static final Color WARNING_FG = new Color(245, 127, 23);
    private static final Color ERROR_BG = new Color(224, 224, 224);
    private static final Color ERROR_FG = new Color(117, 117, 117);
    private static final Color TESTING_BG = new Color(187, 222, 251);
    private static final Color TESTING_FG = new Color(21, 101, 192);

    private static final Font MONO = new Font("Monospaced", Font.PLAIN, 12);
    private static final Font LABEL_FONT = new Font("SansSerif", Font.PLAIN, 11);
    private static final Font SECTION_TITLE = new Font("SansSerif", Font.BOLD, 11);

    private static final String P_SSRF = "cfg.ssrf";
    private static final String P_BAIT = "cfg.bait";
    private static final String P_SSRF_PATH = "cfg.ssrfPath";
    private static final String P_SSRF_SERVER = "cfg.ssrfServer";
    private static final String P_SMUGGLED = "cfg.smuggled";
    private static final String P_VERSION = "cfg.version";
    private static final String P_TIMEOUT = "cfg.timeout";
    private static final String P_DELAY = "cfg.delay";
    private static final String P_THREADS = "cfg.threads";

    private static final int COL_ID = 0;
    private static final int COL_HOST = 1;
    private static final int COL_PAYLOAD = 2;
    private static final int COL_STATUS = 3;
    private static final int COL_CODE1 = 4;
    private static final int COL_CODE2 = 5;
    private static final int COL_LENGTH = 6;
    private static final int COL_TIME = 7;

    private final MontoyaApi api;
    private final AttackEngine engine;
    private JPanel mainPanel;

    private JCheckBox ssrfToggle;
    private JTextField simpleBaitPathField;
    private JTextField ssrfInjectionPathField;
    private JTextField ssrfServerField;
    private JTextField smuggledPathField;
    private JTextField versionField;
    private JTextField timeoutField;
    private JTextField delayField;
    private JTextField threadsField;

    private JButton loadWordlistBtn;
    private JButton runBtn;
    private JButton pauseBtn;
    private JButton stopBtn;
    private JButton clearBtn;
    private JButton exportBtn;
    private JLabel wordlistStatusLabel;
    private JProgressBar progressBar;

    private DefaultTableModel tableModel;
    private JTable resultsTable;
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    private volatile HttpRequestResponse targetRequest;
    private final List<String> loadedWordlist = new CopyOnWriteArrayList<>();
    private final Map<Integer, AttackLog> attackHistory = new ConcurrentHashMap<>();

    public SmugglerUI(MontoyaApi api) {
        this.api = api;
        this.engine = new AttackEngine(api, this);
        buildUI();
        loadPersistedConfig();
    }

    public JComponent getUI() { return mainPanel; }
    public AttackEngine getEngine() { return engine; }

    public void setTargetAndAttack(HttpRequestResponse target) {
        this.targetRequest = target;
        SwingUtilities.invokeLater(this::checkRunButtonState);
        api.logging().logToOutput("Target set: " + target.httpService().host());

        AttackConfig config = buildConfig();
        if (config != null) {
            engine.performSingleAttack(target, config);
        }
    }

    public void saveConfig() {
        try {
            var data = api.persistence().extensionData();
            data.setBoolean(P_SSRF, ssrfToggle.isSelected());
            data.setString(P_BAIT, simpleBaitPathField.getText());
            data.setString(P_SSRF_PATH, ssrfInjectionPathField.getText());
            data.setString(P_SSRF_SERVER, ssrfServerField.getText());
            data.setString(P_SMUGGLED, smuggledPathField.getText());
            data.setString(P_VERSION, versionField.getText());
            data.setString(P_TIMEOUT, timeoutField.getText());
            data.setString(P_DELAY, delayField.getText());
            data.setString(P_THREADS, threadsField.getText());
        } catch (Exception e) {
            api.logging().logToError("Failed to save config: " + e.getMessage());
        }
    }

    // ==========================================================================
    //  UI Construction
    // ==========================================================================

    private void buildUI() {
        mainPanel = new JPanel(new BorderLayout(0, 6));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel topPanel = new JPanel(new BorderLayout(0, 6));
        topPanel.add(buildConfigPanel(), BorderLayout.CENTER);
        topPanel.add(buildControlPanel(), BorderLayout.SOUTH);

        buildResultsTable();
        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180)),
                " Results ", TitledBorder.LEFT, TitledBorder.TOP, SECTION_TITLE));

        requestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JTabbedPane reqTabs = new JTabbedPane();
        reqTabs.addTab("Request", requestViewer.uiComponent());
        JTabbedPane resTabs = new JTabbedPane();
        resTabs.addTab("Response", responseViewer.uiComponent());

        JSplitPane viewerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqTabs, resTabs);
        viewerSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, viewerSplit);
        mainSplit.setResizeWeight(0.4);

        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(mainSplit, BorderLayout.CENTER);
    }

    private JPanel buildConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 5));

        ssrfToggle = new JCheckBox("Enable SSRF-Triggered Smuggling");
        ssrfToggle.setFont(ssrfToggle.getFont().deriveFont(Font.BOLD, 12f));
        ssrfToggle.setToolTipText("Switch between Simple Desync and SSRF-chained attack modes");
        ssrfToggle.addActionListener(e -> { toggleSSRFFields(); saveConfig(); });

        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 2));
        togglePanel.add(ssrfToggle);

        JPanel fieldsPanel = new JPanel(new GridLayout(1, 2, 12, 0));
        fieldsPanel.add(buildConnectionPanel());
        fieldsPanel.add(buildAttackSettingsPanel());

        panel.add(togglePanel, BorderLayout.NORTH);
        panel.add(fieldsPanel, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildConnectionPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(ACCENT),
                " Connection Settings ", TitledBorder.LEFT, TitledBorder.TOP,
                SECTION_TITLE, ACCENT));

        GridBagConstraints c = gbc();

        simpleBaitPathField = monoField("/socket",
                "Backend WebSocket endpoint path");
        ssrfInjectionPathField = monoField("/check-url?server=",
                "SSRF path including parameter name and '='");
        ssrfServerField = monoField("http://127.0.0.1:8000",
                "External server URL for SSRF trigger");

        addRow(panel, c, 0, "Simple Bait Path:", simpleBaitPathField);
        addRow(panel, c, 1, "SSRF Injection Path:", ssrfInjectionPathField);
        addRow(panel, c, 2, "Python Server URL:", ssrfServerField);

        c.gridy = 3; c.weighty = 1.0; c.gridwidth = 2;
        panel.add(Box.createVerticalGlue(), c);

        toggleSSRFFields();
        return panel;
    }

    private JPanel buildAttackSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(ACCENT),
                " Attack Settings ", TitledBorder.LEFT, TitledBorder.TOP,
                SECTION_TITLE, ACCENT));

        GridBagConstraints c = gbc();

        smuggledPathField = monoField("/robots.txt",
                "Target path — use {PAYLOAD} for wordlist substitution");
        versionField = monoField("13",
                "WebSocket handshake version (e.g. 13 or 777)");
        timeoutField = monoField("5000",
                "Socket read timeout in ms (100–60000)");
        delayField = monoField("50",
                "Delay between requests in ms (0–10000)");
        threadsField = monoField("1",
                "Concurrent attack threads (1–50)");

        addRow(panel, c, 0, "Smuggled Path:", smuggledPathField);
        addRow(panel, c, 1, "WS Version:", versionField);
        addRow(panel, c, 2, "Socket Timeout (ms):", timeoutField);
        addRow(panel, c, 3, "Request Delay (ms):", delayField);
        addRow(panel, c, 4, "Threads:", threadsField);

        return panel;
    }

    private JPanel buildControlPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 4));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180)),
                " Wordlist & Controls ", TitledBorder.LEFT, TitledBorder.TOP, SECTION_TITLE));

        JPanel wlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        loadWordlistBtn = new JButton("Load Wordlist");
        loadWordlistBtn.setToolTipText("Load a text file with one payload per line");
        loadWordlistBtn.addActionListener(e -> loadWordlist());
        wordlistStatusLabel = new JLabel("No wordlist loaded");
        wordlistStatusLabel.setForeground(Color.GRAY);
        wlPanel.add(loadWordlistBtn);
        wlPanel.add(wordlistStatusLabel);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        progressBar.setPreferredSize(new Dimension(0, 22));

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        runBtn = new JButton("Run Attack");
        runBtn.setToolTipText("Run a single attack, or iterate through a loaded wordlist");
        runBtn.setEnabled(false);
        runBtn.addActionListener(e -> startAttack());

        pauseBtn = new JButton("Pause");
        pauseBtn.setToolTipText("Pause / resume the running attack");
        pauseBtn.setEnabled(false);
        pauseBtn.addActionListener(e -> togglePause());

        stopBtn = new JButton("Stop");
        stopBtn.setToolTipText("Terminate the current attack");
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopAttack());

        clearBtn = new JButton("Clear Results");
        clearBtn.setToolTipText("Clear all results from the table");
        clearBtn.addActionListener(e -> clearResults());

        exportBtn = new JButton("Export CSV");
        exportBtn.setToolTipText("Export results table to a CSV file");
        exportBtn.addActionListener(e -> exportCSV());

        btnPanel.add(runBtn);
        btnPanel.add(pauseBtn);
        btnPanel.add(stopBtn);
        btnPanel.add(Box.createHorizontalStrut(20));
        btnPanel.add(clearBtn);
        btnPanel.add(exportBtn);

        panel.add(wlPanel, BorderLayout.NORTH);
        panel.add(progressBar, BorderLayout.CENTER);
        panel.add(btnPanel, BorderLayout.SOUTH);
        return panel;
    }

    private void buildResultsTable() {
        String[] cols = {"ID", "Host", "Payload", "Status", "Code 1", "Code 2", "Length", "Time"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) {
                return (c == COL_ID || c == COL_LENGTH) ? Integer.class : String.class;
            }
        };

        resultsTable = new JTable(tableModel);
        resultsTable.setAutoCreateRowSorter(true);
        resultsTable.setRowHeight(24);
        resultsTable.setShowHorizontalLines(true);
        resultsTable.setShowVerticalLines(false);
        resultsTable.setGridColor(new Color(230, 230, 230));
        resultsTable.setSelectionBackground(new Color(51, 153, 255));
        resultsTable.setSelectionForeground(Color.WHITE);
        resultsTable.setFont(new Font("SansSerif", Font.PLAIN, 12));

        // Column widths
        int[] widths = {50, 150, 160, 230, 65, 65, 75, 80};
        int[] maxW   = {60,   0,   0,   0, 80, 80, 100, 100};
        for (int i = 0; i < widths.length; i++) {
            resultsTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
            if (maxW[i] > 0) resultsTable.getColumnModel().getColumn(i).setMaxWidth(maxW[i]);
        }

        // Custom row renderer
        StatusRowRenderer renderer = new StatusRowRenderer();
        for (int i = 0; i < cols.length; i++) {
            resultsTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateEditors();
        });
    }

    // ==========================================================================
    //  Actions & Logic
    // ==========================================================================

    private void startAttack() {
        AttackConfig config = buildConfig();
        if (config == null) return;

        List<String> errors = config.validate();
        if (!errors.isEmpty()) {
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), String.join("\n", errors),
                    "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        HttpRequestResponse target = resolveTarget();
        if (target == null) return;

        if (loadedWordlist.isEmpty()) {
            engine.performSingleAttack(target, config);
        } else {
            setAttackUIState(true);
            progressBar.setValue(0);
            progressBar.setString("Starting...");
            engine.performWordlistAttack(target, config, new ArrayList<>(loadedWordlist));
        }
    }

    private void togglePause() {
        engine.togglePause();
        pauseBtn.setText(engine.isPaused() ? "Resume" : "Pause");
    }

    private void stopAttack() {
        engine.stop();
        setAttackUIState(false);
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        attackHistory.clear();
        HttpService dummy = HttpService.httpService("localhost", 80, false);
        requestViewer.setRequest(HttpRequest.httpRequest(dummy, ByteArray.byteArray("")));
        responseViewer.setResponse(HttpResponse.httpResponse(ByteArray.byteArray("")));
        progressBar.setValue(0);
        progressBar.setString("Ready");
    }

    private void loadWordlist() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(api.userInterface().swingUtils().suiteFrame()) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            loadedWordlist.clear();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (!line.trim().isEmpty()) loadedWordlist.add(line.trim());
                }
                wordlistStatusLabel.setText("Loaded: " + file.getName()
                        + " (" + loadedWordlist.size() + " payloads)");
                wordlistStatusLabel.setForeground(new Color(27, 94, 32));
                checkRunButtonState();
            } catch (IOException ex) {
                wordlistStatusLabel.setText("Error loading file");
                wordlistStatusLabel.setForeground(Color.RED);
                api.logging().logToError("Error loading wordlist: " + ex.getMessage());
            }
        }
    }

    private void exportCSV() {
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), "No results to export.",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("ws_smuggler_results.csv"));
        if (chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame()) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(chooser.getSelectedFile()), StandardCharsets.UTF_8))) {
                StringBuilder hdr = new StringBuilder();
                for (int j = 0; j < tableModel.getColumnCount(); j++) {
                    if (j > 0) hdr.append(",");
                    hdr.append(csvEscape(tableModel.getColumnName(j)));
                }
                pw.println(hdr);

                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    StringBuilder row = new StringBuilder();
                    for (int j = 0; j < tableModel.getColumnCount(); j++) {
                        if (j > 0) row.append(",");
                        Object val = tableModel.getValueAt(i, j);
                        row.append(csvEscape(val != null ? val.toString() : ""));
                    }
                    pw.println(row);
                }
                api.logging().logToOutput(
                        "Exported to: " + chooser.getSelectedFile().getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String csvEscape(String s) {
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    @Override
    public void onAttackStarted(int id, String host, String payload, String timestamp) {
        SwingUtilities.invokeLater(() ->
                tableModel.addRow(new Object[]{
                        id, host, payload != null ? payload : "-",
                        "Testing...", "-", "-", 0, timestamp
                }));
    }

    @Override
    public void onAttackComplete(int id, AttackLog log, ResponseAnalyzer.ResponseAnalysis analysis) {
        attackHistory.put(id, log);
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                Object val = tableModel.getValueAt(i, COL_ID);
                if (val != null && val.equals(id)) {
                    tableModel.setValueAt(analysis.status, i, COL_STATUS);
                    tableModel.setValueAt(analysis.code1, i, COL_CODE1);
                    tableModel.setValueAt(analysis.code2, i, COL_CODE2);
                    tableModel.setValueAt(analysis.responseLength, i, COL_LENGTH);
                    if (resultsTable.getSelectedRow() != -1) updateEditors();
                    break;
                }
            }
        });
    }

    @Override
    public void onAttackError(int id, String errorMessage) {
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                Object val = tableModel.getValueAt(i, COL_ID);
                if (val != null && val.equals(id)) {
                    tableModel.setValueAt("Error: " + errorMessage, i, COL_STATUS);
                    break;
                }
            }
        });
    }

    @Override
    public void onBatchComplete() {
        SwingUtilities.invokeLater(() -> {
            setAttackUIState(false);
            progressBar.setString("Complete");
        });
    }

    @Override
    public void onProgressUpdate(int completed, int total) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setMaximum(total);
            progressBar.setValue(completed);
            int pct = total > 0 ? (int) ((completed * 100.0) / total) : 0;
            progressBar.setString(completed + " / " + total + " (" + pct + "%)");
        });
    }

    /**
     * Resolves the target request based on user right-click context selection.
     */
    private HttpRequestResponse resolveTarget() {
        if (targetRequest != null) return targetRequest;

        JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                "No target set. Right-click a request in Proxy HTTP History\n" +
                "and choose \"Send to WebSocket Smuggler\" first.",
                "No Target", JOptionPane.WARNING_MESSAGE);
        return null;
    }

    private void setAttackUIState(boolean active) {
        SwingUtilities.invokeLater(() -> {
            runBtn.setEnabled(!active && targetRequest != null && !engine.isRunning());
            loadWordlistBtn.setEnabled(!active);
            ssrfToggle.setEnabled(!active);
            pauseBtn.setEnabled(active);
            stopBtn.setEnabled(active);
            pauseBtn.setText("Pause");
            if (!active) checkRunButtonState();
        });
    }

    private void checkRunButtonState() {
        runBtn.setEnabled(targetRequest != null && !engine.isRunning());
    }

    private void toggleSSRFFields() {
        boolean isSSRF = ssrfToggle.isSelected();
        simpleBaitPathField.setEnabled(!isSSRF);
        ssrfInjectionPathField.setEnabled(isSSRF);
        ssrfServerField.setEnabled(isSSRF);
    }

    private void updateEditors() {
        try {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow == -1) return;
            int modelRow = resultsTable.convertRowIndexToModel(viewRow);
            int id = (Integer) tableModel.getValueAt(modelRow, COL_ID);
            AttackLog log = attackHistory.get(id);
            if (log != null) {
                requestViewer.setRequest(log.getRequest());
                responseViewer.setResponse(log.getResponse());
            }
        } catch (Exception ex) {
            api.logging().logToError("Editor update error: " + ex.getMessage());
        }
    }

    private AttackConfig buildConfig() {
        try {
            return new AttackConfig(
                    ssrfToggle.isSelected(),
                    simpleBaitPathField.getText().trim(),
                    ssrfInjectionPathField.getText().trim(),
                    ssrfServerField.getText().trim(),
                    smuggledPathField.getText().trim(),
                    versionField.getText().trim(),
                    Integer.parseInt(timeoutField.getText().trim()),
                    Integer.parseInt(delayField.getText().trim()),
                    Integer.parseInt(threadsField.getText().trim())
            );
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                    "Timeout, Delay, and Threads must be valid numbers.",
                    "Input Error", JOptionPane.WARNING_MESSAGE);
            return null;
        }
    }

    private void loadPersistedConfig() {
        try {
            var data = api.persistence().extensionData();
            Boolean ssrf = data.getBoolean(P_SSRF);
            if (ssrf != null) ssrfToggle.setSelected(ssrf);

            setIfPresent(data.getString(P_BAIT), simpleBaitPathField);
            setIfPresent(data.getString(P_SSRF_PATH), ssrfInjectionPathField);
            setIfPresent(data.getString(P_SSRF_SERVER), ssrfServerField);
            setIfPresent(data.getString(P_SMUGGLED), smuggledPathField);
            setIfPresent(data.getString(P_VERSION), versionField);
            setIfPresent(data.getString(P_TIMEOUT), timeoutField);
            setIfPresent(data.getString(P_DELAY), delayField);
            setIfPresent(data.getString(P_THREADS), threadsField);

            toggleSSRFFields();
        } catch (Exception e) {
            api.logging().logToError("Failed to load persisted config: " + e.getMessage());
        }
    }

    private void setIfPresent(String value, JTextField field) {
        if (value != null && !value.isEmpty()) field.setText(value);
    }

    private JTextField monoField(String defaultText, String tooltip) {
        JTextField f = new JTextField(defaultText, 22);
        f.setFont(MONO);
        f.setToolTipText(tooltip);
        f.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusLost(java.awt.event.FocusEvent e) { saveConfig(); }
        });
        return f;
    }

    private GridBagConstraints gbc() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 8, 4, 8);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    private void addRow(JPanel panel, GridBagConstraints c,
                        int row, String label, JComponent field) {
        c.gridx = 0; c.gridy = row; c.gridwidth = 1; c.weightx = 0; c.weighty = 0;
        JLabel lbl = new JLabel(label);
        lbl.setFont(LABEL_FONT);
        panel.add(lbl, c);
        c.gridx = 1; c.weightx = 1.0;
        panel.add(field, c);
    }

    // ==========================================================================
    //  Custom Table Renderer — color-codes entire rows by status
    // ==========================================================================

    private class StatusRowRenderer extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {

            Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                int modelRow = table.convertRowIndexToModel(row);
                Object statusObj = table.getModel().getValueAt(modelRow, COL_STATUS);
                String status = statusObj != null ? statusObj.toString() : "";

                Color bg;
                Color fg;
                if (status.contains("Smuggling")) {
                    bg = SMUGGLING_BG; fg = SMUGGLING_FG;
                } else if (status.contains("Pipelining")) {
                    bg = SAFE_BG; fg = SAFE_FG;
                } else if (status.contains("Single Response")) {
                    bg = WARNING_BG; fg = WARNING_FG;
                } else if (status.startsWith("Error")) {
                    bg = ERROR_BG; fg = ERROR_FG;
                } else if (status.contains("Testing")) {
                    bg = TESTING_BG; fg = TESTING_FG;
                } else {
                    bg = table.getBackground(); fg = table.getForeground();
                }
                c.setBackground(bg);
                c.setForeground(fg);
            }

            // Bold the status column
            if (column == COL_STATUS) {
                c.setFont(c.getFont().deriveFont(Font.BOLD));
            }

            return c;
        }
    }
}
