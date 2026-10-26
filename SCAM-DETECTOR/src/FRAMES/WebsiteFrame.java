
package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;

public class WebsiteFrame extends JFrame {

    private JTextField urlField;

    public WebsiteFrame() {

        setTitle("Website Scam Detection");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel heading = new JLabel("WEBSITE SCAM DETECTION");
        heading.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel urlLabel = new JLabel("Enter Website URL:");

        urlField = new JTextField(25);

        JButton scanButton = new JButton("SCAN");

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

        // Check for empty input
        if (url.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please enter a website URL.",
                    "Missing URL",
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        try {
            // Analyze the website
            URLAnalyzer.AnalysisResult result =
                    URLAnalyzer.analyze(url);

            StringBuilder message = new StringBuilder();

            message.append("Classification: ")
                   .append(result.classification)
                   .append("\nRisk Score: ")
                   .append(result.riskScore)
                   .append("/100\n\nReasons:\n");

            for (String reason : result.reasons) {
                message.append("- ")
                       .append(reason)
                       .append("\n");
            }

            // Save the scan to the database
            DatabaseManager.saveScan(
                    "Website",
                    url,
                    result.classification,
                    result.riskScore
            );

            // Display the result
            JOptionPane.showMessageDialog(
                    this,
                    message.toString(),
                    "Website Scan Result",
                    JOptionPane.INFORMATION_MESSAGE
            );

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "An error occurred while scanning the website:\n"
                            + ex.getMessage(),
                    "Scan Error",
                    JOptionPane.ERROR_MESSAGE
            );

            ex.printStackTrace();
        }
    }

    public static void main(String[] args) {
        DatabaseManager.initializeDatabase();
        SwingUtilities.invokeLater(() -> new WebsiteFrame());
    }
}
