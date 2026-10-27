
package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;
import java.util.ArrayList;

public class WebsiteFrame extends JFrame {

    private JTextField urlField;
    private JButton scanButton;

    public WebsiteFrame() {

        setTitle("Website Scam Detection");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel heading = new JLabel(
                "WEBSITE SCAM DETECTION",
                SwingConstants.CENTER);

        JLabel urlLabel = new JLabel("Enter Website URL:");

        urlField = new JTextField(25);

        scanButton = new JButton("SCAN");

        JPanel inputPanel = new JPanel();
        inputPanel.add(urlLabel);
        inputPanel.add(urlField);

        add(heading, BorderLayout.NORTH);
        add(inputPanel, BorderLayout.CENTER);
        add(scanButton, BorderLayout.SOUTH);

        scanButton.addActionListener(e -> scanWebsite());

        setVisible(true);
    }

    private void scanWebsite() {

        String url = urlField.getText().trim();

        if (url.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please enter a website URL.",
                    "Missing URL",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        scanButton.setEnabled(false);
        scanButton.setText("SCANNING...");

        SwingWorker<ScanOutcome, Void> worker =
                new SwingWorker<ScanOutcome, Void>() {

            @Override
            protected ScanOutcome doInBackground() {

                // Run the existing URL analyzer.
                URLAnalyzer.AnalysisResult rules =
                        URLAnalyzer.analyze(url);

                String classification = rules.classification;
                int riskScore = rules.riskScore;

                ArrayList<String> reasons =
                        new ArrayList<>(rules.reasons);

                String explanation = "";

                // Try the online AI service.
                try {
                    GroqAIService.AIResult ai =
                            GroqAIService.analyze("website URL", url);

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

                    boolean highRisk =
                            aiClass.contains("HIGH RISK")
                            || rules.classification
                                    .toUpperCase().contains("HIGH RISK")
                            || rules.classification
                                    .toUpperCase().contains("SUSPICIOUS")
                            || riskScore >= 50;

                    boolean suspicious =
                            aiClass.contains("SUSPICIOUS")
                            || aiClass.contains("NEEDS REVIEW")
                            || riskScore >= 20;

                    if (highRisk) {
                        classification = "HIGH RISK";
                    } else if (suspicious) {
                        classification = "SUSPICIOUS";
                    } else {
                        classification = "LOW RISK";
                    }

                } catch (Exception ex) {
                    // Keep the existing analyzer's result if AI fails.
                    classification = rules.classification;
                    riskScore = rules.riskScore;
                }

                // Shorten the rule-based classification for display/history.
                String upper = classification.toUpperCase();

                if (upper.contains("HIGH RISK")
                        || upper.contains("SUSPICIOUS")) {
                    classification = "HIGH RISK".equals(upper)
                            ? "HIGH RISK"
                            : upper.contains("HIGH RISK")
                                    ? "HIGH RISK" : "SUSPICIOUS";
                } else if (upper.contains("NEEDS REVIEW")) {
                    classification = "SUSPICIOUS";
                } else if (upper.contains("NO OBVIOUS WARNING SIGNS")
                        || upper.contains("LOW RISK")) {
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
                scanButton.setText("SCAN");

                try {
                    ScanOutcome result = get();

                    // Save the result to SQLite.
                    DatabaseManager.saveScan(
                            "Website",
                            url,
                            result.classification,
                            result.riskScore);

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

                    if (!result.explanation.isEmpty()) {
                        output.append("\nExplanation:\n")
                              .append(result.explanation)
                              .append("\n");
                    }

                    JOptionPane.showMessageDialog(
                            WebsiteFrame.this,
                            output.toString(),
                            "Website Scan Result",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(
                            WebsiteFrame.this,
                            "Website scan failed:\n" + ex.getMessage(),
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

        DatabaseManager.initializeDatabase();

        SwingUtilities.invokeLater(() -> new WebsiteFrame());
    }
}
