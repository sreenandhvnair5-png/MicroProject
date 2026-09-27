package FRAMES;

import javax.swing.*;

public class WebsiteFrame extends JFrame {

    public WebsiteFrame() {

        setTitle("Website Scam Detection");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel heading = new JLabel("WEBSITE SCAM DETECTION");
        heading.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel urlLabel = new JLabel("Enter Website URL:");

        JTextField urlField = new JTextField();

        JButton scanButton = new JButton("SCAN");

        add(heading, "North");
        add(urlLabel, "West");
        add(urlField, "Center");
        add(scanButton, "South");

        setVisible(true);
    }

    public static void main(String[] args) {
        new WebsiteFrame();
    }
}
