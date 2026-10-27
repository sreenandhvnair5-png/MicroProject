package FRAMES;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashSet;
import java.util.Set;

public class PhoneFrame extends JFrame {

    private JTextField phoneField;
    private JTextArea contextArea;
    private JButton scanButton;

    public PhoneFrame() {

        setTitle("Phone Scam Detection");
        setSize(600, 450);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel heading = new JLabel(
                "PHONE SCAM DETECTION",
                SwingConstants.CENTER);
        heading.setFont(new Font("SansSerif", Font.BOLD, 22));

        JPanel inputPanel = new JPanel(new GridLayout(2, 1, 5, 5));

        JPanel phonePanel = new JPanel(new BorderLayout(5, 5));
        phonePanel.add(new JLabel("Phone Number:"), BorderLayout.NORTH);

        phoneField = new JTextField();
        phoneField.setFont(new Font("SansSerif", Font.PLAIN, 16));
        phonePanel.add(phoneField, BorderLayout.CENTER);

        JPanel contextPanel = new JPanel(new BorderLayout(5, 5));
        contextPanel.add(
                new JLabel("Message or call details (optional):"),
                BorderLayout.NORTH);

        contextArea = new JTextArea(6, 30);
        contextArea.setLineWrap(true);
        contextArea.setWrapStyleWord(true);

        contextPanel.add(
                new JScrollPane(contextArea),
                BorderLayout.CENTER);

        inputPanel.add(phonePanel);
        inputPanel.add(contextPanel);

        scanButton = new JButton("SCAN PHONE NUMBER");
        scanButton.addActionListener(e -> scanPhone());

        mainPanel.add(heading, BorderLayout.NORTH);
        mainPanel.add(inputPanel, BorderLayout.CENTER);
        mainPanel.add(scanButton, BorderLayout.SOUTH);

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
                    "Input Required",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        String content = "Phone Number: " + phone
                + "\nCall or message details: " + context;

        scanButton.setEnabled(false);
        scanButton.setText("ANALYZING...");

        SwingWorker<ScanResult, Void> worker =
                new SwingWorker<ScanResult, Void>() {

            @Override
            protected ScanResult doInBackground() {

                int ruleScore = 0;
                String ruleResult = "";
                String aiResult = "";

                try {
                	PhoneAnalyzer.AnalysisResult phoneResult =
                	        PhoneAnalyzer.analyze(phone, context);

                	ruleResult = "Classification: " + phoneResult.classification
                	        + "\nRisk Score: " + phoneResult.riskScore
                	        + "\nReasons: " + String.join(", ", phoneResult.reasons);
                } catch (Exception ex) {
                    ruleResult = "";
                }

                int localScore = extractScore(ruleResult);
             // If no message or call details were provided,
             // assess the phone number format only.
             if (context.trim().isEmpty()) {

                 String localClassification;

                 if (localScore >= 70) {
                     localClassification = "HIGH RISK";
                 } else if (localScore >= 35) {
                     localClassification = "SUSPICIOUS";
                 } else {
                     localClassification = "LOW RISK";
                 }

                 String localReasons = extractSection(ruleResult, "Reasons");

                 if (localReasons.isEmpty()) {
                     localReasons =
                             "No suspicious message or call details were provided.";
                 }

                 return new ScanResult(
                         localClassification,
                         localScore,
                         localReasons,
                         "Phone number format alone cannot confirm whether "
                         + "a caller is fraudulent."
                 );
             }

                try {
                    GroqAIService.AIResult result =
                            GroqAIService.analyze("phone scam", content);

                    if (result != null) {
                        aiResult = result.classification
                                + "\nRisk Score: " + result.riskScore
                                + "\nReasons: " + result.reasons
                                + "\nExplanation: " + result.explanation;
                    }
                } catch (Exception ex) {
                    aiResult = "";
                }

                int aiScore = extractScore(aiResult);

             // Start with the local analyzer's score.
             ruleScore = localScore;

             // Only use the AI score if it provides specific warning signs.
             String aiReasons = extractSection(aiResult, "Reasons");

             if (!aiResult.isEmpty()
                     && !aiReasons.isEmpty()
                     && !aiReasons.toLowerCase().contains("no warning signs")
                     && !aiReasons.toLowerCase().contains("none identified")) {

                 ruleScore = Math.max(localScore, aiScore);
             }

             String classification;

             if (ruleScore >= 70) {
                 classification = "HIGH RISK";
             } else if (ruleScore >= 35) {
                 classification = "SUSPICIOUS";
             } else {
                 classification = "LOW RISK";
             }

                String reasons = combineText(
                        extractSection(aiResult, "Reasons"),
                        extractSection(ruleResult, "Reasons"));

                String explanation =
                        extractSection(aiResult, "Explanation");

                if (explanation.isEmpty()) {
                    explanation =
                            extractSection(ruleResult, "Explanation");
                }

                if (reasons.isEmpty()) {
                    reasons = "No specific warning signs were returned.";
                }

                if (explanation.isEmpty()) {
                    explanation =
                            "Assessment based on the supplied phone "
                            + "number and call or message details.";
                }

                return new ScanResult(
                        classification, ruleScore, reasons, explanation);
            }

            @Override
            protected void done() {

                try {
                    ScanResult result = get();

                    DatabaseManager.saveScan(
                            "Phone",
                            content,
                            result.classification,
                            result.score);

                    JTextArea output = new JTextArea(
                            "Classification: " + result.classification
                            + "\nRisk Score: " + result.score + "/100"
                            + "\n\nReasons:\n" + result.reasons
                            + "\n\nExplanation:\n" + result.explanation);

                    output.setEditable(false);
                    output.setLineWrap(true);
                    output.setWrapStyleWord(true);
                    output.setFont(
                            new Font("SansSerif", Font.PLAIN, 14));
                    output.setCaretPosition(0);

                    JScrollPane scrollPane = new JScrollPane(output);
                    scrollPane.setPreferredSize(
                            new Dimension(480, 300));

                    JOptionPane.showMessageDialog(
                            PhoneFrame.this,
                            scrollPane,
                            "Phone Scan Result",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception ex) {

                    JOptionPane.showMessageDialog(
                            PhoneFrame.this,
                            "The scan could not be completed. Please try again.",
                            "Scan Error",
                            JOptionPane.ERROR_MESSAGE);

                    ex.printStackTrace();

                } finally {
                    scanButton.setEnabled(true);
                    scanButton.setText("SCAN PHONE NUMBER");
                }
            }
        };

        worker.execute();
    }

    private int extractScore(String text) {

        if (text == null) {
            return 0;
        }

        java.util.regex.Matcher matcher =
                java.util.regex.Pattern.compile(
                        "(?i)risk\\s*score\\s*:?\\s*(\\d{1,3})")
                        .matcher(text);

        if (matcher.find()) {
            try {
                return Math.max(0, Math.min(
                        100, Integer.parseInt(matcher.group(1))));
            } catch (NumberFormatException ex) {
                return 0;
            }
        }

        return 0;
    }

    private String extractClassification(String text) {

        if (text == null) {
            return "";
        }

        String upper = text.toUpperCase();

        if (upper.contains("HIGH RISK")) {
            return "HIGH RISK";
        }

        if (upper.contains("SUSPICIOUS")) {
            return "SUSPICIOUS";
        }

        if (upper.contains("LOW RISK")) {
            return "LOW RISK";
        }

        return "";
    }

    private String extractSection(String text, String heading) {

        if (text == null || text.trim().isEmpty()) {
            return "";
        }

        String[] lines = text.split("\\r?\\n");
        StringBuilder section = new StringBuilder();
        boolean collecting = false;

        for (String line : lines) {

            String trimmed = line.trim();
            String lower = trimmed.toLowerCase();

            if (lower.startsWith(heading.toLowerCase() + ":")) {
                collecting = true;

                String remainder =
                        trimmed.substring(trimmed.indexOf(':') + 1).trim();

                if (!remainder.isEmpty()) {
                    section.append(remainder).append(" ");
                }

                continue;
            }

            if (collecting &&
                    (lower.startsWith("explanation:")
                    || lower.startsWith("recommended action:")
                    || lower.startsWith("warning signs:")
                    || lower.startsWith("risk score:")
                    || lower.startsWith("classification:"))) {
                break;
            }

            if (collecting) {
                section.append(trimmed).append(" ");
            }
        }

        return section.toString().trim();
    }

    private String combineText(String first, String second) {

        Set<String> items = new LinkedHashSet<String>();

        addItems(items, first);
        addItems(items, second);

        if (items.isEmpty()) {
            return "";
        }

        StringBuilder result = new StringBuilder();

        for (String item : items) {
            if (result.length() > 0) {
                result.append("\n");
            }

            result.append("- ").append(item);
        }

        return result.toString();
    }

    private void addItems(Set<String> items, String text) {

        if (text == null || text.trim().isEmpty()) {
            return;
        }

        for (String item : text.split("\\r?\\n|;")) {
            String cleaned = item.trim()
                    .replaceFirst("^[-•*\\s]+", "")
                    .trim();

            if (!cleaned.isEmpty()) {
                items.add(cleaned);
            }
        }
    }

    private static class ScanResult {

        String classification;
        int score;
        String reasons;
        String explanation;

        ScanResult(
                String classification,
                int score,
                String reasons,
                String explanation) {

            this.classification = classification;
            this.score = score;
            this.reasons = reasons;
            this.explanation = explanation;
        }
    }

    public static void main(String[] args) {

        DatabaseManager.initializeDatabase();

        SwingUtilities.invokeLater(() -> new PhoneFrame());
    }
}