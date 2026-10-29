
package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;

public class EmailFrame extends JFrame {

    private JTextField subjectField;
    private JTextArea bodyArea;
    private JButton scanButton;
    private JButton clearButton;

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
        subjectPanel.add(
                new JLabel("Email Subject:"), BorderLayout.NORTH);
        subjectPanel.add(subjectField, BorderLayout.CENTER);

        JPanel bodyPanel = new JPanel(new BorderLayout(5, 5));
        bodyPanel.add(new JLabel("Email Body:"), BorderLayout.NORTH);
        bodyPanel.add(new JScrollPane(bodyArea), BorderLayout.CENTER);

        inputPanel.add(subjectPanel, BorderLayout.NORTH);
        inputPanel.add(bodyPanel, BorderLayout.CENTER);

        scanButton = new JButton("SCAN EMAIL");
        clearButton = new JButton("CLEAR");

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

        scanButton.setEnabled(false);
        clearButton.setEnabled(false);
        scanButton.setText("SCANNING...");

        String emailContent =
                "Subject: " + subject + "\n\nBody:\n" + body;

        SwingWorker<ScanOutcome, Void> worker =
                new SwingWorker<ScanOutcome, Void>() {

            @Override
            protected ScanOutcome doInBackground() {

                // Run the existing email analyzer.
                EmailAnalyzer.AnalysisResult rules =
                        EmailAnalyzer.analyze(subject, body);

                String classification = rules.classification;
                int riskScore = rules.riskScore;

                ArrayList<String> reasons =
                        new ArrayList<>(rules.reasons);

                String explanation = "";

                // Try online AI analysis.
                try {
                    GroqAIService.AIResult ai =
                            GroqAIService.analyze("email", emailContent);

                    riskScore = Math.max(
                            rules.riskScore,
                            ai.riskScore);

                    if (ai.reasons != null
                            && !ai.reasons.trim().isEmpty()) {
                        reasons.add(ai.reasons.trim());
                    }

                    if (ai.explanation != null) {
                        explanation = ai.explanation.trim();
                    }

                    String aiClass = ai.classification == null
                            ? ""
                            : ai.classification.toUpperCase();

                    String ruleClass =
                            rules.classification.toUpperCase();

                    boolean highRisk =
                            riskScore >= 50
                            || aiClass.contains("HIGH RISK")
                            || ruleClass.contains("HIGH RISK");

                    boolean suspicious =
                            riskScore >= 20
                            || aiClass.contains("SUSPICIOUS")
                            || aiClass.contains("NEEDS REVIEW")
                            || ruleClass.contains("SUSPICIOUS");

                    if (highRisk) {
                        classification = "HIGH RISK";
                    } else if (suspicious) {
                        classification = "SUSPICIOUS";
                    } else {
                        classification = "LOW RISK";
                    }

                } catch (Exception ex) {
                    // If AI fails, keep the rule-based result.
                    classification = rules.classification;
                    riskScore = rules.riskScore;
                }

                // Normalize the classification.
                String upper = classification.toUpperCase();

                if (upper.contains("HIGH RISK")) {
                    classification = "HIGH RISK";
                } else if (upper.contains("SUSPICIOUS")
                        || upper.contains("NEEDS REVIEW")) {
                    classification = "SUSPICIOUS";
                } else if (upper.contains("LOW RISK")
                        || upper.contains("NO MAJOR FLAGS")
                        || upper.contains("NO OBVIOUS WARNING")) {
                    classification = "LOW RISK";
                }

                return new ScanOutcome(
                        classification,
                        riskScore,
                        reasons,
                        explanation);
            }

            @Override
            protected void done() {

                scanButton.setEnabled(true);
                clearButton.setEnabled(true);
                scanButton.setText("SCAN EMAIL");

                try {
                    ScanOutcome result = get();

                    // Save the scan to SQLite.
                    // Database failures must not stop result display.
                    DatabaseManager.saveScan(
                            "Email",
                            emailContent,
                            result.classification,
                            result.riskScore);

                    StringBuilder output = new StringBuilder();

                    output.append("Classification: ")
                          .append(result.classification)
                          .append("\nRisk Score: ")
                          .append(result.riskScore)
                          .append("/100\n\nReasons:\n");

                    if (result.reasons.isEmpty()) {
                        output.append("- No specific reasons available.\n");
                    } else {
                        for (String reason : result.reasons) {
                            output.append("- ")
                                  .append(reason)
                                  .append("\n");
                        }
                    }

                    if (result.explanation != null
                            && !result.explanation.isEmpty()) {
                        output.append("\nExplanation:\n")
                              .append(result.explanation)
                              .append("\n");
                    }

                    // Fixed-size, scrollable result popup.
                    JTextArea resultArea =
                            new JTextArea(output.toString());

                    resultArea.setEditable(false);
                    resultArea.setLineWrap(true);
                    resultArea.setWrapStyleWord(true);
                    resultArea.setCaretPosition(0);
                    resultArea.setFont(new Font(
                            "SansSerif", Font.PLAIN, 14));

                    JScrollPane resultScroll =
                            new JScrollPane(resultArea);

                    resultScroll.setPreferredSize(
                            new Dimension(550, 300));

                    JOptionPane.showMessageDialog(
                            EmailFrame.this,
                            resultScroll,
                            "Email Scan Result",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(
                            EmailFrame.this,
                            "Email scan failed:\n" + ex.getMessage(),
                            "Scan Error",
                            JOptionPane.ERROR_MESSAGE);

                    ex.printStackTrace();
                }
            }
        };

        worker.execute();
    }

    private static class ScanOutcome {

        String classification;
        int riskScore;
        ArrayList<String> reasons;
        String explanation;

        ScanOutcome(
                String classification,
                int riskScore,
                ArrayList<String> reasons,
                String explanation) {

            this.classification = classification;
            this.riskScore = riskScore;
            this.reasons = reasons;
            this.explanation = explanation;
        }
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> {
            DatabaseManager.initializeDatabase();
            new EmailFrame();
        });
    }
}
