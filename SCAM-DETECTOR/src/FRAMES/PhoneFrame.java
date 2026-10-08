package FRAMES;

import javax.swing.*;

public class PhoneFrame extends JFrame {
    public PhoneFrame() {
        setTitle("Phone Scam Detection");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);
        JLabel heading = new JLabel("PHONE SCAM DETECTION");
        heading.setHorizontalAlignment(SwingConstants.CENTER);
        JLabel phoneLabel = new JLabel("Enter Phone Number:");
        JTextField phoneField = new JTextField();
        JButton scanButton = new JButton("SCAN");
        add(heading, "North");
        add(phoneLabel, "West");
        add(phoneField, "Center");
        add(scanButton, "South");
        setVisible(true);
    }

    public static void main(String[] args) {
        new PhoneFrame();
    }
}