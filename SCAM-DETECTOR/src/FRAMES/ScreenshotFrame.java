
package FRAMES;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
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
                "No screenshot selected",
                SwingConstants.CENTER);

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
                        "This image cannot be previewed by Java ImageIO. "
                      + "Please use a PNG or JPG screenshot.",
                        "Unsupported Image",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }

            int maxWidth = 550;
            int maxHeight = 320;

            double scale = Math.min(
                    (double) maxWidth / image.getWidth(),
                    (double) maxHeight / image.getHeight());

            scale = Math.min(scale, 1.0);

            int width = Math.max(1, (int) (image.getWidth() * scale));
            int height = Math.max(1, (int) (image.getHeight() * scale));

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

        File imageToScan = selectedFile;

        uploadButton.setEnabled(false);
        scanButton.setEnabled(false);
        clearButton.setEnabled(false);

        scanButton.setText("ANALYZING...");

        SwingWorker<String, Void> worker = new SwingWorker<>() {

            @Override
            protected String doInBackground() throws Exception {

                return AdditionalAnalyzer.analyzeScreenshot(
                        imageToScan.toPath());
            }

            @Override
            protected void done() {

                try {
                    String analysis = get();

                    // Determine a provisional category from the AI report.
                    String lowerAnalysis =
                            analysis.toLowerCase(java.util.Locale.ROOT);

                    String classification = "Analysis completed";
                    int riskScore = 0;

                    if (lowerAnalysis.contains("high risk")
                            || lowerAnalysis.contains("likely scam")
                            || lowerAnalysis.contains("scam detected")) {

                        classification = "SUSPICIOUS";
                        riskScore = 80;

                    } else if (lowerAnalysis.contains("medium risk")
                            || lowerAnalysis.contains("suspicious")) {

                        classification = "SUSPICIOUS";
                        riskScore = 50;

                    } else if (lowerAnalysis.contains("low risk")
                            || lowerAnalysis.contains("appears safe")) {

                        classification = "Low risk";
                        riskScore = 10;
                    }

                    // Save the successful AI analysis in SQLite.
                    DatabaseManager.saveScan(
                            "Screenshot",
                            "File: " + imageToScan.getName()
                                    + "\n\nAI Analysis:\n" + analysis,
                            classification,
                            riskScore
                    );

                    JTextArea resultArea = new JTextArea(20, 50);
                    resultArea.setText(analysis);
                    resultArea.setEditable(false);
                    resultArea.setLineWrap(true);
                    resultArea.setWrapStyleWord(true);
                    resultArea.setCaretPosition(0);
                    resultArea.setFont(
                            new Font("SansSerif", Font.PLAIN, 14));

                    JScrollPane resultScroll =
                            new JScrollPane(resultArea);
                    resultScroll.setPreferredSize(
                            new Dimension(550, 350));

                    JOptionPane.showMessageDialog(
                            ScreenshotFrame.this,
                            resultScroll,
                            "AI Screenshot Analysis",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception ex) {

                    Throwable cause = ex.getCause();

                    String message = cause != null
                            ? cause.getMessage()
                            : ex.getMessage();

                    JOptionPane.showMessageDialog(
                            ScreenshotFrame.this,
                            "Analysis or database save failed:\n"
                            + (message == null
                                    ? "An unexpected error occurred."
                                    : message),
                            "Analysis Error",
                            JOptionPane.ERROR_MESSAGE);

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

    private void clearImage() {

        selectedFile = null;

        imageLabel.setIcon(null);
        imageLabel.setText("No screenshot selected");
        fileLabel.setText("Choose a screenshot to begin.");

        scanButton.setEnabled(false);
    }

    public static void main(String[] args) {
        DatabaseManager.initializeDatabase();
        SwingUtilities.invokeLater(ScreenshotFrame::new);
    }
}
