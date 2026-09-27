package FRAMES;

import javax.swing.*;

public class MessageFrame extends JFrame {

    public MessageFrame() {

        setTitle("Message Scam Detection");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel heading = new JLabel("MESSAGE SCAM DETECTION");
        heading.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel messageLabel = new JLabel("Enter Message:");

        JTextArea messageArea = new JTextArea();
       

        JButton scanButton = new JButton("SCAN");

        add(heading, "North");
        add(messageLabel, "West");
        add(messageArea, "Center");
        add(scanButton, "South");

        setVisible(true);
    }

    public static void main(String[] args) {
        new MessageFrame();
    }
}