
package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
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

        heading.setFont(new Font("SansSerif", Font.BOLD, 20));

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

                // 1. Run rule-based URL analysis.
                URLAnalyzer.AnalysisResult rules =
                        URLAnalyzer.analyze(url);

                String classification = rules.classification;
                int riskScore = rules.riskScore;

                // Keep only rule-based reasons in this list.
                ArrayList<String> ruleReasons =
                        new ArrayList<>(rules.reasons);

                // Keep AI explanation separately.
                String explanation = "";

                // 2. Run AI analysis.
                try {
                    GroqAIService.AIResult ai =
                            GroqAIService.analyze("website URL", url);

                    // Combine scores, using the higher score.
                    riskScore = Math.max(
                            rules.riskScore,
                            ai.riskScore);

                    // IMPORTANT:
                    // Do not add ai.reasons to ruleReasons.
                    // Reasons must remain rule-based only.

                    if (ai.explanation != null) {
                        explanation = ai.explanation.trim();
                    }

                    String aiClass = ai.classification == null
                            ? ""
                            : ai.classification.toUpperCase();

                    String ruleClass =
                            rules.classification == null
                                    ? ""
                                    : rules.classification.toUpperCase();

                    boolean highRisk =
                            aiClass.contains("HIGH RISK")
                            || ruleClass.contains("HIGH RISK")
                            || ruleClass.contains("SUSPICIOUS")
                            || riskScore >= 50;

                    boolean suspicious =
                            aiClass.contains("SUSPICIOUS")
                            || aiClass.contains("NEEDS REVIEW")
                            || ruleClass.contains("NEEDS REVIEW")
                            || riskScore >= 20;

                    // 3. Determine final classification.
                    if (highRisk) {
                        classification = "HIGH RISK";
                    } else if (suspicious) {
                        classification = "SUSPICIOUS";
                    } else {
                        classification = "LOW RISK";
                    }

                } catch (Exception ex) {

                    // If AI fails, continue with rule-based analysis.
                    classification = rules.classification;
                    riskScore = rules.riskScore;
                    explanation = "";
                }

                // Normalize the rule-based classification for display.
                String upper = classification.toUpperCase();

                if (upper.contains("HIGH RISK")) {
                    classification = "HIGH RISK";
                } else if (upper.contains("SUSPICIOUS")
                        || upper.contains("NEEDS REVIEW")) {
                    classification = "SUSPICIOUS";
                } else if (upper.contains("LOW RISK")
                        || upper.contains("NO OBVIOUS WARNING SIGNS")) {
                    classification = "LOW RISK";
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

                    // Display long results in a scrollable popup.
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
                            new Dimension(600, 320));

                    JOptionPane.showMessageDialog(
                            WebsiteFrame.this,
                            resultScrollPane,
                            "Website Scan Result",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception ex) {

                    JOptionPane.showMessageDialog(
                            WebsiteFrame.this,
                            "Website scan failed:\n"
                                    + ex.getMessage(),
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
            new WebsiteFrame();
        });
    }
}
