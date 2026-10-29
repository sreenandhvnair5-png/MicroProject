
package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Dimension;
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

                // 1. Run rule-based analysis.
                MessageAnalyzer.AnalysisResult rules =
                        MessageAnalyzer.analyze(message);

                String classification = rules.classification;
                int riskScore = rules.riskScore;

                // Keep ONLY rule-based reasons in this list.
                ArrayList<String> ruleReasons =
                        new ArrayList<>(rules.reasons);

                // AI-generated explanation is stored separately.
                String explanation = "";

                // 2. Run AI analysis.
                try {
                    GroqAIService.AIResult ai =
                            GroqAIService.analyze("message", message);

                    // Use the higher of the two risk scores.
                    riskScore = Math.max(
                            rules.riskScore,
                            ai.riskScore);

                    // Store only the AI explanation here.
                    // Do NOT add ai.reasons to ruleReasons.
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

                    // 3. Determine the final classification.
                    if (riskScore >= 50
                            || aiHighRisk || rulesHighRisk) {

                        classification =
                                "HIGH RISK - POSSIBLE SCAM";

                    } else if (riskScore >= 20
                            || aiSuspicious || rulesSuspicious) {

                        classification =
                                "SUSPICIOUS - REVIEW CAREFULLY";

                    } else {

                        classification =
                                "LOW RISK - NO MAJOR FLAGS FOUND";
                    }

                } catch (Exception ex) {

                    // If AI fails, continue with rule-based results.
                    classification = rules.classification;
                    riskScore = rules.riskScore;
                    explanation = "";
                }

                return new ScanOutcome(
                        classification,
                        riskScore,
                        ruleReasons,
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

                    // Build the result popup.
                    StringBuilder output = new StringBuilder();

                    output.append("Classification: ")
                          .append(formatClassification(
                                  result.classification))
                          .append("\n");

                    output.append("Risk Score: ")
                          .append(result.riskScore)
                          .append("/100\n\n");

                    // SECTION 1: Rule-based reasons only.
                    output.append("Reasons:\n");

                    for (String reason : result.reasons) {
                        output.append("- ")
                              .append(reason)
                              .append("\n");
                    }

                    // SECTION 2: AI-generated explanation only.
                    if (result.explanation != null
                            && !result.explanation.isEmpty()) {

                        output.append("\nExplanation:\n")
                              .append(result.explanation)
                              .append("\n");
                    }

                    // Use a wrapped text area for long results.
                    JTextArea resultArea =
                            new JTextArea(output.toString());

                    resultArea.setEditable(false);
                    resultArea.setLineWrap(true);
                    resultArea.setWrapStyleWord(true);
                    resultArea.setFont(
                            new Font("SansSerif", Font.PLAIN, 16));
                    resultArea.setCaretPosition(0);

                    JScrollPane resultScrollPane =
                            new JScrollPane(resultArea);

                    resultScrollPane.setPreferredSize(
                            new Dimension(760, 400));

                    JOptionPane.showMessageDialog(
                            MessageFrame.this,
                            resultScrollPane,
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
