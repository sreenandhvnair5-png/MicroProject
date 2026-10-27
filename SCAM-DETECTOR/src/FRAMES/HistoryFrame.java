package FRAMES;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.json.JSONArray;
import org.json.JSONObject;

public class HistoryFrame extends JFrame {

    private JTable historyTable;
    private DefaultTableModel tableModel;
    private JButton refreshButton;

    private static final String SUPABASE_URL =
        "https://pwdgvyqeskwnumqeosaq.supabase.co/functions/v1/scam-analyze";

    private static final String SUPABASE_KEY =
        "sb_publishable_kwSsttjTjStIFD_yBqf0hQ_D4HhLGlK";

    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();

    public HistoryFrame() {

        setTitle("Scan History");
        setSize(1100, 500);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        JLabel heading = new JLabel("SCAN HISTORY");
        heading.setHorizontalAlignment(SwingConstants.CENTER);
        heading.setFont(new Font("Arial", Font.BOLD, 22));

        String[] columns = {
            "ID", "Type", "Scanned Content",
            "Result", "Risk Score", "Date & Time"
        };

        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        historyTable = new JTable(tableModel);
        historyTable.setRowHeight(25);
        historyTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        int[] widths = {60, 100, 300, 150, 100, 250};

        for (int i = 0; i < widths.length; i++) {
            historyTable.getColumnModel()
                .getColumn(i).setPreferredWidth(widths[i]);
        }

        JScrollPane scrollPane = new JScrollPane(historyTable);

        refreshButton = new JButton("Refresh");
        JButton detailsButton = new JButton("View Details");
        JButton closeButton = new JButton("Close");

        refreshButton.addActionListener(e -> loadHistory());
        detailsButton.addActionListener(e -> showDetails());
        closeButton.addActionListener(e -> dispose());

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(refreshButton);
        buttonPanel.add(detailsButton);
        buttonPanel.add(closeButton);

        add(heading, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        loadHistory();
        setVisible(true);
    }

    private void loadHistory() {

        if (!refreshButton.isEnabled()) {
            return;
        }

        refreshButton.setEnabled(false);
        tableModel.setRowCount(0);

        new SwingWorker<JSONArray, Void>() {

            @Override
            protected JSONArray doInBackground() throws Exception {

                JSONObject requestBody = new JSONObject();
                requestBody.put("action", "history");

                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(SUPABASE_URL))
                    .timeout(Duration.ofSeconds(30))
                    .header("apikey", SUPABASE_KEY)
                    .header("Authorization", "Bearer " + SUPABASE_KEY)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                        requestBody.toString()))
                    .build();

                HttpResponse<String> response = CLIENT.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
                );

                if (response.statusCode() < 200
                        || response.statusCode() >= 300) {
                    throw new Exception(
                        "HTTP " + response.statusCode()
                        + ": " + response.body()
                    );
                }

                JSONObject json = new JSONObject(response.body());

                if (!json.optBoolean("success", false)) {
                    throw new Exception(
                        json.optString("error", "History request failed.")
                    );
                }

                return json.getJSONArray("scans");
            }

            @Override
            protected void done() {

                try {
                    JSONArray scans = get();

                    for (int i = 0; i < scans.length(); i++) {

                        JSONObject scan = scans.getJSONObject(i);
                        String resultText = scan.optString("result", "");

                        try {
                            JSONObject resultJson = new JSONObject(resultText);
                            resultText = resultJson.optString(
                                "classification", resultText);
                        } catch (Exception ignored) {
                            // Keep the original result if it isn't JSON.
                        }

                        Object[] row = {
                            scan.optLong("id"),
                            scan.optString("scan_type"),
                            scan.optString("scanned_content"),
                            resultText,
                            scan.optInt("risk_score"),
                            scan.optString("scan_time")
                        };

                        tableModel.addRow(row);
                    }

                    if (scans.length() == 0) {
                        JOptionPane.showMessageDialog(
                            HistoryFrame.this,
                            "No cloud scan history found.");
                    }

                } catch (Exception ex) {

                    Throwable cause = ex.getCause() != null
                        ? ex.getCause() : ex;

                    JOptionPane.showMessageDialog(
                        HistoryFrame.this,
                        "Could not load cloud history.\n"
                            + cause.getMessage(),
                        "History Error",
                        JOptionPane.ERROR_MESSAGE);

                } finally {
                    refreshButton.setEnabled(true);
                }
            }

        }.execute();
    }

    private void showDetails() {

        int selectedRow = historyTable.getSelectedRow();

        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(
                this, "Please select a scan from the table.");
            return;
        }

        String type = String.valueOf(
            tableModel.getValueAt(selectedRow, 1));
        String content = String.valueOf(
            tableModel.getValueAt(selectedRow, 2));
        String result = String.valueOf(
            tableModel.getValueAt(selectedRow, 3));
        String riskScore = String.valueOf(
            tableModel.getValueAt(selectedRow, 4));
        String dateTime = String.valueOf(
            tableModel.getValueAt(selectedRow, 5));

        JTextArea details = new JTextArea(
            "Scan Type: " + type
            + "\n\nScanned Content:\n" + content
            + "\n\nClassification: " + result
            + "\n\nRisk Score: " + riskScore
            + "\n\nDate & Time: " + dateTime
        );

        details.setEditable(false);
        details.setLineWrap(true);
        details.setWrapStyleWord(true);
        details.setCaretPosition(0);

        JScrollPane detailsScroll = new JScrollPane(details);
        detailsScroll.setPreferredSize(new Dimension(500, 300));

        JOptionPane.showMessageDialog(
            this,
            detailsScroll,
            "Scan Details",
            JOptionPane.INFORMATION_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new HistoryFrame());
    }
}