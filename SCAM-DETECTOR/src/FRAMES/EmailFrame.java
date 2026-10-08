package FRAMES;

import javax.swing.*;

public class EmailFrame extends JFrame {
    public EmailFrame() {
        setTitle("Email Scam Detection");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel heading = new JLabel("EMAIL SCAM DETECTION");
        heading.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel emailLabel = new JLabel("Enter Email:");
        JTextArea emailArea = new JTextArea();
        JButton scanButton = new JButton("SCAN");

        add(heading, "North");
        add(emailLabel, "West");
        add(emailArea, "Center");
        add(scanButton, "South");

        setVisible(true);
    }

    public static void main(String[] args) {
        new EmailFrame();
    }
}