
package FRAMES;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class HistoryFrame extends JFrame {

    private JTable historyTable;
    private DefaultTableModel tableModel;
    private JButton refreshButton;

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

        refreshButton.setEnabled(false);
        tableModel.setRowCount(0);

        new SwingWorker<Void, Object[]>() {

            @Override
            protected Void doInBackground() throws Exception {

                String sql =
                    "SELECT id, scan_type, scanned_content, "
                    + "result, risk_score, scan_time "
                    + "FROM scan_history ORDER BY id DESC";

                try (Connection con = DatabaseManager.getConnection();
                     PreparedStatement stmt = con.prepareStatement(sql);
                     ResultSet rs = stmt.executeQuery()) {

                    while (rs.next()) {

                        String resultText = rs.getString("result");

                        if (resultText == null) {
                            resultText = "";
                        }

                        publish(new Object[] {
                            rs.getLong("id"),
                            rs.getString("scan_type"),
                            rs.getString("scanned_content"),
                            resultText,
                            rs.getInt("risk_score"),
                            rs.getString("scan_time")
                        });
                    }
                }

                return null;
            }

            @Override
            protected void process(java.util.List<Object[]> rows) {
                for (Object[] row : rows) {
                    tableModel.addRow(row);
                }
            }

            @Override
            protected void done() {

                try {
                    get();

                    if (tableModel.getRowCount() == 0) {
                        JOptionPane.showMessageDialog(
                            HistoryFrame.this,
                            "No local scan history found.");
                    }

                } catch (Exception ex) {

                    Throwable cause = ex.getCause() != null
                        ? ex.getCause() : ex;

                    JOptionPane.showMessageDialog(
                        HistoryFrame.this,
                        "Could not load local history.\n"
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
