
package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Font;

public class EmailFrame extends JFrame {

    private JTextField subjectField;
    private JTextArea bodyArea;

    public EmailFrame() {

        setTitle("Email Scam Detection");
        setSize(700, 550);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel heading = new JLabel(
                "EMAIL SCAM DETECTION",
                SwingConstants.CENTER);
        heading.setFont(new Font("SansSerif", Font.BOLD, 22));

        subjectField = new JTextField();

        bodyArea = new JTextArea(12, 40);
        bodyArea.setLineWrap(true);
        bodyArea.setWrapStyleWord(true);

        JPanel inputPanel = new JPanel(new BorderLayout(5, 10));

        JPanel subjectPanel = new JPanel(new BorderLayout(5, 5));
        subjectPanel.add(new JLabel("Email Subject:"),
                BorderLayout.NORTH);
        subjectPanel.add(subjectField, BorderLayout.CENTER);

        JPanel bodyPanel = new JPanel(new BorderLayout(5, 5));
        bodyPanel.add(new JLabel("Email Body:"), BorderLayout.NORTH);
        bodyPanel.add(new JScrollPane(bodyArea), BorderLayout.CENTER);

        inputPanel.add(subjectPanel, BorderLayout.NORTH);
        inputPanel.add(bodyPanel, BorderLayout.CENTER);

        JButton scanButton = new JButton("SCAN EMAIL");
        JButton clearButton = new JButton("CLEAR");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(scanButton);
        buttonPanel.add(clearButton);

        scanButton.addActionListener(e -> scanEmail());

        clearButton.addActionListener(e -> {
            subjectField.setText("");
            bodyArea.setText("");
        });

        mainPanel.add(heading, BorderLayout.NORTH);
        mainPanel.add(inputPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
        setVisible(true);
    }

    private void scanEmail() {

        String subject = subjectField.getText().trim();
        String body = bodyArea.getText().trim();

        if (subject.isEmpty() && body.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please enter an email subject or body to scan.",
                    "Empty Email",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            // Analyze using your existing EmailAnalyzer
            EmailAnalyzer.AnalysisResult result =
                    EmailAnalyzer.analyze(subject, body);

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
                  + "not a guarantee that an email is safe or fraudulent.");

            // Save subject and body together so the history
            // retains the complete email that was analyzed.
            String emailContent =
                    "Subject: " + subject + "\n\nBody:\n" + body;

            DatabaseManager.saveScan(
                    "Email",
                    emailContent,
                    result.classification,
                    result.riskScore
            );

            JOptionPane.showMessageDialog(
                    this,
                    output.toString(),
                    "Email Scan Result",
                    JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "Email scan failed:\n" + ex.getMessage(),
                    "Scan Error",
                    JOptionPane.ERROR_MESSAGE);

            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        DatabaseManager.initializeDatabase();
        SwingUtilities.invokeLater(() -> new EmailFrame());
    }
}
