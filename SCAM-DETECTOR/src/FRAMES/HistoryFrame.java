
package FRAMES;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.Connection;
import java.sql.ResultSet;

public class HistoryFrame extends JFrame {

    private JTable historyTable;
    private DefaultTableModel tableModel;

    public HistoryFrame() {

        setTitle("Scan History");
        setSize(950, 450);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

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

        JScrollPane scrollPane = new JScrollPane(historyTable);

        JButton refreshButton = new JButton("Refresh");
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

        // Load saved scans when the window opens
        loadHistory();

        setVisible(true);
    }

    private void loadHistory() {

        tableModel.setRowCount(0);

        try (Connection con = DatabaseManager.getConnection();
             ResultSet rs = DatabaseManager.getAllScans(con)) {

            while (rs.next()) {
                Object[] row = {
                    rs.getInt("id"),
                    rs.getString("scan_type"),
                    rs.getString("scanned_content"),
                    rs.getString("result"),
                    rs.getInt("risk_score"),
                    rs.getString("scan_time")
                };

                tableModel.addRow(row);
            }

            if (tableModel.getRowCount() == 0) {
                System.out.println("No scan history found.");
            }

        } catch (Exception e) {
            JOptionPane.showMessageDialog(
                this,
                "Could not load scan history.\n" + e.getMessage(),
                "Database Error",
                JOptionPane.ERROR_MESSAGE
            );

            e.printStackTrace();
        }
    }

    private void showDetails() {

        int selectedRow = historyTable.getSelectedRow();

        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(
                this,
                "Please select a scan from the table."
            );
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
            + "\n\nResult:\n" + result
            + "\n\nRisk Score: " + riskScore
            + "\n\nDate & Time: " + dateTime
        );

        details.setEditable(false);
        details.setLineWrap(true);
        details.setWrapStyleWord(true);
        details.setCaretPosition(0);

        JScrollPane detailsScroll = new JScrollPane(details);
        detailsScroll.setPreferredSize(new Dimension(450, 300));

        JOptionPane.showMessageDialog(
            this,
            detailsScroll,
            "Scan Details",
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    public static void main(String[] args) {
        DatabaseManager.initializeDatabase();
        SwingUtilities.invokeLater(() -> new HistoryFrame());
    }
}
