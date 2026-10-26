
package FRAMES;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import javax.imageio.ImageIO;

public class QRFrame extends JFrame {

    private File selectedFile;
    private JLabel imageLabel;
    private JLabel fileLabel;
    private JButton scanButton;

    public QRFrame() {

        setTitle("QR Scam Detection");
        setSize(650, 500);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel heading = new JLabel(
                "QR CODE SCAM DETECTION",
                SwingConstants.CENTER);

        heading.setFont(new Font("SansSerif", Font.BOLD, 20));

        imageLabel = new JLabel(
                "No QR image selected",
                SwingConstants.CENTER);

        fileLabel = new JLabel("Upload a QR image to begin.");

        JButton uploadButton = new JButton("UPLOAD QR IMAGE");
        scanButton = new JButton("SCAN QR");
        JButton clearButton = new JButton("CLEAR");

        scanButton.setEnabled(false);

        uploadButton.addActionListener(e -> chooseImage());
        scanButton.addActionListener(e -> scanImage());
        clearButton.addActionListener(e -> clearImage());

        JPanel buttons = new JPanel();
        buttons.add(uploadButton);
        buttons.add(scanButton);
        buttons.add(clearButton);

        JPanel center = new JPanel(new BorderLayout(5, 5));
        center.add(fileLabel, BorderLayout.NORTH);
        center.add(new JScrollPane(imageLabel), BorderLayout.CENTER);

        add(heading, BorderLayout.NORTH);
        add(center, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        setVisible(true);
    }

    private void chooseImage() {

        JFileChooser chooser = new JFileChooser();

        chooser.setFileFilter(
                new javax.swing.filechooser.FileNameExtensionFilter(
                        "PNG and JPG images", "png", "jpg", "jpeg"));

        if (chooser.showOpenDialog(this)
                != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = chooser.getSelectedFile();

        try {
            BufferedImage image = ImageIO.read(file);

            if (image == null) {
                JOptionPane.showMessageDialog(this,
                        "Please select a valid PNG or JPG image.");
                return;
            }

            int maxWidth = 500;
            int maxHeight = 300;

            double scale = Math.min(
                    1.0,
                    Math.min((double) maxWidth / image.getWidth(),
                             (double) maxHeight / image.getHeight()));

            Image preview = image.getScaledInstance(
                    Math.max(1, (int) (image.getWidth() * scale)),
                    Math.max(1, (int) (image.getHeight() * scale)),
                    Image.SCALE_SMOOTH);

            selectedFile = file;
            imageLabel.setIcon(new ImageIcon(preview));
            imageLabel.setText("");
            fileLabel.setText("Selected: " + file.getName());
            scanButton.setEnabled(true);

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Could not open the image.");
        }
    }

    private void scanImage() {

        if (selectedFile == null) {
            return;
        }

        File file = selectedFile;
        scanButton.setEnabled(false);
        scanButton.setText("SCANNING...");

        SwingWorker<String, Void> worker = new SwingWorker<>() {

            @Override
            protected String doInBackground() throws Exception {
                return QRAnalyzer.scanQR(file);
            }

            @Override
            protected void done() {

                try {
                    String report = get();

                    // Extract classification and risk score
                    String classification = "Unable to classify";
                    int riskScore = 0;

                    if (report.contains("SUSPICIOUS")) {
                        classification = "SUSPICIOUS";
                        riskScore = 70;
                    } else if (report.contains(
                            "NO OBVIOUS WARNING SIGNS DETECTED")) {
                        classification = "No obvious warning signs";
                        riskScore = 0;
                    } else if (report.contains("NO QR CODE FOUND")) {
                        classification = "No QR code found";
                    } else if (report.startsWith("ERROR:")) {
                        classification = "Scan error";
                    }

                    // Save the QR scan report to SQLite
                    DatabaseManager.saveScan(
                            "QR",
                            "File: " + file.getName()
                                    + "\n\n" + report,
                            classification,
                            riskScore
                    );

                    JTextArea area = new JTextArea(15, 45);
                    area.setText(report);
                    area.setEditable(false);
                    area.setLineWrap(true);
                    area.setWrapStyleWord(true);
                    area.setCaretPosition(0);

                    JOptionPane.showMessageDialog(
                            QRFrame.this,
                            new JScrollPane(area),
                            "QR Scan Results",
                            JOptionPane.INFORMATION_MESSAGE);

                } catch (Exception e) {
                    JOptionPane.showMessageDialog(
                            QRFrame.this,
                            "Scan failed: " + e.getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                } finally {
                    scanButton.setEnabled(selectedFile != null);
                    scanButton.setText("SCAN QR");
                }
            }
        };

        worker.execute();
    }

    private void clearImage() {
        selectedFile = null;
        imageLabel.setIcon(null);
        imageLabel.setText("No QR image selected");
        fileLabel.setText("Upload a QR image to begin.");
        scanButton.setEnabled(false);
    }

    public static void main(String[] args) {
        DatabaseManager.initializeDatabase();
        SwingUtilities.invokeLater(QRFrame::new);
    }
}
