package FRAMES;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.imageio.ImageIO;

public class ScreenshotFrame extends JFrame {

    private JLabel imageLabel;
    private JLabel fileLabel;
    private File selectedFile;

    private JButton uploadButton;
    private JButton scanButton;
    private JButton clearButton;

    public ScreenshotFrame() {

        setTitle("Screenshot Scam Detection");
        setSize(700, 550);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel heading = new JLabel(
                "SCREENSHOT SCAM DETECTION",
                SwingConstants.CENTER);
        heading.setFont(new Font("SansSerif", Font.BOLD, 22));

        imageLabel = new JLabel(
                "No screenshot selected", SwingConstants.CENTER);

        fileLabel = new JLabel("Choose a screenshot to begin.");

        uploadButton = new JButton("UPLOAD SCREENSHOT");
        scanButton = new JButton("ANALYZE SCREENSHOT");
        clearButton = new JButton("CLEAR");

        scanButton.setEnabled(false);

        uploadButton.addActionListener(e -> chooseImage());
        scanButton.addActionListener(e -> scanImage());
        clearButton.addActionListener(e -> clearImage());

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(uploadButton);
        buttonPanel.add(scanButton);
        buttonPanel.add(clearButton);

        JPanel centerPanel = new JPanel(new BorderLayout(5, 5));
        centerPanel.add(fileLabel, BorderLayout.NORTH);

        JScrollPane imageScrollPane = new JScrollPane(imageLabel);
        imageScrollPane.setPreferredSize(new Dimension(620, 350));

        centerPanel.add(imageScrollPane, BorderLayout.CENTER);

        mainPanel.add(heading, BorderLayout.NORTH);
        mainPanel.add(centerPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
        setVisible(true);
    }

    private void chooseImage() {

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select a Screenshot");

        chooser.setFileFilter(
                new javax.swing.filechooser.FileNameExtensionFilter(
                        "Image Files (PNG, JPG, JPEG, WEBP)",
                        "png", "jpg", "jpeg", "webp"));

        int result = chooser.showOpenDialog(this);

        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = chooser.getSelectedFile();

        try {
            BufferedImage image = ImageIO.read(file);

            if (image == null) {
                JOptionPane.showMessageDialog(
                        this,
                        "Please select a PNG or JPG screenshot.",
                        "Unsupported Image",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }

            double scale = Math.min(
                    Math.min(550.0 / image.getWidth(),
                            320.0 / image.getHeight()),
                    1.0);

            int width = Math.max(
                    1, (int) (image.getWidth() * scale));
            int height = Math.max(
                    1, (int) (image.getHeight() * scale));

            Image scaledImage = image.getScaledInstance(
                    width, height, Image.SCALE_SMOOTH);

            selectedFile = file;

            imageLabel.setIcon(new ImageIcon(scaledImage));
            imageLabel.setText("");
            fileLabel.setText("Selected: " + file.getName());

            scanButton.setEnabled(true);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(
                    this,
                    "Could not open the selected image.",
                    "Image Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void scanImage() {

        if (selectedFile == null) {
            JOptionPane.showMessageDialog(
                    this, "Please upload a screenshot first.");
            return;
        }

        final File imageToScan = selectedFile;

        uploadButton.setEnabled(false);
        scanButton.setEnabled(false);
        clearButton.setEnabled(false);
        scanButton.setText("ANALYZING...");

        SwingWorker<String, Void> worker =
                new SwingWorker<String, Void>() {

            @Override
            protected String doInBackground() throws Exception {

                return AdditionalAnalyzer.analyzeScreenshot(
                        imageToScan.toPath());
            }

            @Override
            protected void done() {

                try {
                    String analysis = get();

                    if (analysis == null || analysis.trim().isEmpty()) {
                        throw new Exception(
                                "No analysis was returned.");
                    }

                    int riskScore = extractRiskScore(analysis);
                    String classification =
                            extractClassification(analysis);

                    if (classification.equals("UNKNOWN")) {
                        if (riskScore >= 70) {
                            classification = "HIGH RISK";
                        } else if (riskScore >= 35) {
                            classification = "SUSPICIOUS";
                        } else {
                            classification = "LOW RISK";
                        }
                    }

                    if (classification.equals("HIGH RISK")) {
                        riskScore = Math.max(riskScore, 70);
                    } else if (classification.equals("SUSPICIOUS")) {
                        riskScore = Math.max(riskScore, 35);
                    }

                    String reasons = extractSection(
                            analysis,
                            "Warning signs",
                            "Explanation",
                            "Recommended action");

                    String explanation = extractSection(
                            analysis,
                            "Explanation",
                            "Recommended action");

                    if (reasons.isEmpty()) {
                        reasons = "Review the visible content "
                                + "for suspicious links or requests.";
                    }

                    if (explanation.isEmpty()) {
                        explanation =
                                "Assessment based on the screenshot content.";
                    }

                    String output =
                            "Classification: " + classification
                            + "\nRisk Score: " + riskScore + "/100"
                            + "\n\nReasons:\n" + reasons
                            + "\n\nExplanation:\n" + explanation;

                    DatabaseManager.saveScan(
                            "Screenshot",
                            "File: " + imageToScan.getName()
                                    + "\n\n" + analysis,
                            classification,
                            riskScore);

                    JTextArea resultArea = new JTextArea(18, 48);
                    resultArea.setText(output);
                    resultArea.setEditable(false);
                    resultArea.setLineWrap(true);
                    resultArea.setWrapStyleWord(true);
                    resultArea.setCaretPosition(0);
                    resultArea.setFont(
                            new Font("SansSerif", Font.PLAIN, 14));

                    JScrollPane resultScroll =
                            new JScrollPane(resultArea);
                    resultScroll.setPreferredSize(
                            new Dimension(530, 330));

                    JOptionPane.showMessageDialog(
                            ScreenshotFrame.this,
                            resultScroll,
                            "Screenshot Scan Result",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception ex) {

                    JOptionPane.showMessageDialog(
                            ScreenshotFrame.this,
                            "Screenshot analysis failed. "
                                    + "Please try again.",
                            "Analysis Error",
                            JOptionPane.ERROR_MESSAGE);

                    ex.printStackTrace();

                } finally {
                    uploadButton.setEnabled(true);
                    scanButton.setEnabled(selectedFile != null);
                    clearButton.setEnabled(true);
                    scanButton.setText("ANALYZE SCREENSHOT");
                }
            }
        };

        worker.execute();
    }

    private int extractRiskScore(String analysis) {

        Matcher matcher = Pattern.compile(
                "(?i)risk\\s*score\\s*:?\\s*(\\d{1,3})")
                .matcher(analysis);

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

    private String extractClassification(String analysis) {

        Matcher matcher = Pattern.compile(
                "(?im)^\\s*(?:\\d+[.)]\\s*)?"
                + "classification\\s*:\\s*"
                + "(HIGH\\s+RISK|SUSPICIOUS|LOW\\s+RISK)")
                .matcher(analysis);

        if (matcher.find()) {
            return matcher.group(1)
                    .toUpperCase()
                    .replaceAll("\\s+", " ");
        }

        return "UNKNOWN";
    }

    private String extractSection(
            String analysis,
            String startHeading,
            String... endHeadings) {

        String lower = analysis.toLowerCase();
        String startMarker = startHeading.toLowerCase();

        int start = lower.indexOf(startMarker);

        if (start < 0) {
            return "";
        }

        start += startMarker.length();

        if (start < analysis.length()
                && analysis.charAt(start) == ':') {
            start++;
        }

        int end = analysis.length();

        for (String heading : endHeadings) {
            int position = lower.indexOf(
                    heading.toLowerCase(), start);

            if (position >= 0 && position < end) {
                end = position;
            }
        }

        String section = analysis.substring(start, end).trim();

        return section.replaceAll("^[\\s:.-]+", "").trim();
    }

    private void clearImage() {

        selectedFile = null;

        imageLabel.setIcon(null);
        imageLabel.setText("No screenshot selected");
        fileLabel.setText("Choose a screenshot to begin.");

        scanButton.setEnabled(false);
    }

    public static void main(String[] args) {

        DatabaseManager.initializeDatabase();

        SwingUtilities.invokeLater(
                () -> new ScreenshotFrame());
    }
}