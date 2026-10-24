package FRAMES;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Font;

public class MessageFrame extends JFrame {

    private JTextArea messageArea;

    public MessageFrame() {

        setTitle("Message / SMS Scam Detection");
        setSize(650, 500);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        // Main container
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Heading
        JLabel heading = new JLabel(
                "MESSAGE / SMS SCAM DETECTION",
                SwingConstants.CENTER);

        heading.setFont(new Font("SansSerif", Font.BOLD, 20));

        // Instruction
        JLabel instruction = new JLabel(
                "Paste the message you want to check:");

        // Text area for entering a message
        messageArea = new JTextArea(10, 40);
        messageArea.setLineWrap(true);
        messageArea.setWrapStyleWord(true);
        messageArea.setFont(new Font("SansSerif", Font.PLAIN, 14));

        JScrollPane scrollPane = new JScrollPane(messageArea);

        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.add(instruction, BorderLayout.NORTH);
        inputPanel.add(scrollPane, BorderLayout.CENTER);

        // Buttons
        JButton scanButton = new JButton("SCAN MESSAGE");
        JButton clearButton = new JButton("CLEAR");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(scanButton);
        buttonPanel.add(clearButton);

        // Button actions
        scanButton.addActionListener(e -> scanMessage());

        clearButton.addActionListener(e -> messageArea.setText(""));

        // Arrange the interface
        mainPanel.add(heading, BorderLayout.NORTH);
        mainPanel.add(inputPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
        setVisible(true);
    }

    private void scanMessage() {

        String message = messageArea.getText();

        MessageAnalyzer.AnalysisResult result =
                MessageAnalyzer.analyze(message);

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

        output.append(
                "\nNote: This is a basic rule-based check, "
              + "not a guarantee that the message is safe or fraudulent.");

        JOptionPane.showMessageDialog(
                this,
                output.toString(),
                "Message Scan Result",
                JOptionPane.INFORMATION_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new MessageFrame());
    }
}
