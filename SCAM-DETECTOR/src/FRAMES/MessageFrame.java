
package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Font;
import java.util.ArrayList;

public class MessageFrame extends JFrame {

    private JTextArea messageArea;
    private JButton scanButton;
    private JButton clearButton;

    public MessageFrame() {

        setTitle("Message / SMS Scam Detection");
        setSize(650, 500);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel heading = new JLabel(
                "MESSAGE / SMS SCAM DETECTION",
                SwingConstants.CENTER);

        heading.setFont(new Font("SansSerif", Font.BOLD, 20));

        JLabel instruction = new JLabel(
                "Paste the message you want to check:");

        messageArea = new JTextArea(10, 40);
        messageArea.setLineWrap(true);
        messageArea.setWrapStyleWord(true);
        messageArea.setFont(new Font("SansSerif", Font.PLAIN, 14));

        JScrollPane scrollPane = new JScrollPane(messageArea);

        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.add(instruction, BorderLayout.NORTH);
        inputPanel.add(scrollPane, BorderLayout.CENTER);

        scanButton = new JButton("SCAN MESSAGE");
        clearButton = new JButton("CLEAR");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(scanButton);
        buttonPanel.add(clearButton);

        scanButton.addActionListener(e -> scanMessage());

        clearButton.addActionListener(e -> messageArea.setText(""));

        mainPanel.add(heading, BorderLayout.NORTH);
        mainPanel.add(inputPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
        setVisible(true);
    }

    private void scanMessage() {

        String message = messageArea.getText().trim();

        if (message.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please enter a message to scan.",
                    "Empty Message",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        scanButton.setEnabled(false);
        clearButton.setEnabled(false);
        scanButton.setText("SCANNING...");

        SwingWorker<ScanOutcome, Void> worker =
                new SwingWorker<ScanOutcome, Void>() {

            @Override
            protected ScanOutcome doInBackground() {

                // Run the existing message analyzer first.
                MessageAnalyzer.AnalysisResult rules =
                        MessageAnalyzer.analyze(message);

                String classification = rules.classification;
                int riskScore = rules.riskScore;

                ArrayList<String> reasons =
                        new ArrayList<>(rules.reasons);

                String explanation = "";

                // Try the online AI service.
                try {
                    GroqAIService.AIResult ai =
                            GroqAIService.analyze("message", message);

                    // Keep the higher risk score.
                    riskScore = Math.max(
                            rules.riskScore,
                            ai.riskScore);

                    // Add additional reasons without technical labels.
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

                    boolean aiHighRisk =
                            aiClass.contains("HIGH RISK");

                    boolean rulesHighRisk =
                            rules.classification
                                    .toUpperCase()
                                    .contains("HIGH RISK");

                    boolean aiSuspicious =
                            aiClass.contains("SUSPICIOUS");

                    boolean rulesSuspicious =
                            rules.classification
                                    .toUpperCase()
                                    .contains("SUSPICIOUS");

                    // Determine the final classification.
                    if (riskScore >= 50
                            || aiHighRisk || rulesHighRisk) {

                        classification = "HIGH RISK - POSSIBLE SCAM";

                    } else if (riskScore >= 20
                            || aiSuspicious || rulesSuspicious) {

                        classification = "SUSPICIOUS - REVIEW CAREFULLY";

                    } else {
                        classification = "LOW RISK - NO MAJOR FLAGS FOUND";
                    }

                } catch (Exception ex) {

                    // If the service is unavailable, keep the
                    // existing analyzer's result.
                    classification = rules.classification;
                    riskScore = rules.riskScore;
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
                scanButton.setText("SCAN MESSAGE");

                try {
                    ScanOutcome result = get();

                    // Save the final result to SQLite.
                    DatabaseManager.saveScan(
                            "Message",
                            message,
                            result.classification,
                            result.riskScore);

                    // Build a clean result popup.
                    StringBuilder output = new StringBuilder();

                    output.append("Classification: ")
                          .append(formatClassification(
                                  result.classification))
                          .append("\nRisk Score: ")
                          .append(result.riskScore)
                          .append("/100\n\n");

                    output.append("Reasons:\n");

                    for (String reason : result.reasons) {
                        output.append("- ")
                              .append(reason)
                              .append("\n");
                    }

                    if (!result.explanation.isEmpty()) {
                        output.append("\nExplanation:\n")
                              .append(result.explanation)
                              .append("\n");
                    }

                    JOptionPane.showMessageDialog(
                            MessageFrame.this,
                            output.toString(),
                            "Message Scan Result",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception ex) {

                    JOptionPane.showMessageDialog(
                            MessageFrame.this,
                            "Message scan failed:\n"
                                    + ex.getMessage(),
                            "Scan Error",
                            JOptionPane.ERROR_MESSAGE);

                    ex.printStackTrace();
                }
            }
        };

        worker.execute();
    }

    // Show a short classification in the popup.
    private String formatClassification(String classification) {

        if (classification == null) {
            return "UNKNOWN";
        }

        String value = classification.toUpperCase();

        if (value.contains("HIGH RISK")) {
            return "HIGH RISK";
        }

        if (value.contains("SUSPICIOUS")) {
            return "SUSPICIOUS";
        }

        if (value.contains("LOW RISK")) {
            return "LOW RISK";
        }

        return classification;
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

        DatabaseManager.initializeDatabase();

        SwingUtilities.invokeLater(
                () -> new MessageFrame());
    }
}
