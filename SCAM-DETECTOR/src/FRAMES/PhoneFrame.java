
package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Font;

public class PhoneFrame extends JFrame {

    private JTextField phoneField;
    private JTextArea contextArea;

    public PhoneFrame() {

        setTitle("Phone Scam Detection");
        setSize(650, 500);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel heading = new JLabel(
                "PHONE SCAM DETECTION",
                SwingConstants.CENTER);
        heading.setFont(new Font("SansSerif", Font.BOLD, 22));

        phoneField = new JTextField();

        contextArea = new JTextArea(10, 35);
        contextArea.setLineWrap(true);
        contextArea.setWrapStyleWord(true);

        JPanel phonePanel = new JPanel(new BorderLayout(5, 5));
        phonePanel.add(new JLabel("Indian Mobile Number:"),
                BorderLayout.NORTH);
        phonePanel.add(phoneField, BorderLayout.CENTER);

        JPanel contextPanel = new JPanel(new BorderLayout(5, 5));
        contextPanel.add(new JLabel(
                "Message or call context (optional):"),
                BorderLayout.NORTH);
        contextPanel.add(new JScrollPane(contextArea),
                BorderLayout.CENTER);

        JPanel inputPanel = new JPanel(new BorderLayout(10, 10));
        inputPanel.add(phonePanel, BorderLayout.NORTH);
        inputPanel.add(contextPanel, BorderLayout.CENTER);

        JButton scanButton = new JButton("SCAN NUMBER");
        JButton clearButton = new JButton("CLEAR");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(scanButton);
        buttonPanel.add(clearButton);

        scanButton.addActionListener(e -> scanPhone());

        clearButton.addActionListener(e -> {
            phoneField.setText("");
            contextArea.setText("");
        });

        mainPanel.add(heading, BorderLayout.NORTH);
        mainPanel.add(inputPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
        setVisible(true);
    }

    private void scanPhone() {

        String phone = phoneField.getText().trim();
        String context = contextArea.getText().trim();

        if (phone.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please enter a phone number.",
                    "Missing Number",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            // Analyze using your existing PhoneAnalyzer
            PhoneAnalyzer.AnalysisResult result =
                    PhoneAnalyzer.analyze(phone, context);

            StringBuilder output = new StringBuilder();

            output.append("Classification: ")
                  .append(result.classification)
                  .append("\nRisk Score: ")
                  .append(result.riskScore)
                  .append("/100\n\nReasons:\n");

            for (String reason : result.reasons) {
                output.append("- ")
                      .append(reason)
                      .append("\n");
            }

            output.append(
                    "\nThis is a basic rule-based assessment, "
                  + "not a verified phone-number reputation check.");

            // Save number and context in the database
            String scannedContent =
                    "Phone Number: " + phone
                    + "\nContext: " + context;

            DatabaseManager.saveScan(
                    "Phone",
                    scannedContent,
                    result.classification,
                    result.riskScore
            );

            JOptionPane.showMessageDialog(
                    this,
                    output.toString(),
                    "Phone Scan Result",
                    JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "Phone scan failed:\n" + ex.getMessage(),
                    "Scan Error",
                    JOptionPane.ERROR_MESSAGE);

            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        DatabaseManager.initializeDatabase();
        SwingUtilities.invokeLater(() -> new PhoneFrame());
    }
}
