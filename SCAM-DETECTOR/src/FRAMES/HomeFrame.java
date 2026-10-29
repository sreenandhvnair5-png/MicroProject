package FRAMES;

import javax.swing.*;
import java.awt.*;

public class HomeFrame extends JFrame {

    
    private final Color backgroundColor = new Color(15, 23, 42);
    private final Color panelColor = new Color(30, 41, 59);
    private final Color accentColor = new Color(59, 130, 246);
    private final Color textColor = new Color(241, 245, 249);
    private final Color mutedColor = new Color(148, 163, 184);

    public HomeFrame() {
    	DatabaseManager.initializeDatabase();
        
        setTitle("Scam Detection System");
        setSize(850, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(true);

       
        JPanel mainPanel = new JPanel(new BorderLayout(20, 20));
        mainPanel.setBackground(backgroundColor);
        mainPanel.setBorder(
                BorderFactory.createEmptyBorder(30, 35, 30, 35)
        );

        
        JLabel title = new JLabel("SCAM DETECTION SYSTEM");
        title.setFont(new Font("SansSerif", Font.BOLD, 28));
        title.setForeground(textColor);
        title.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subtitle = new JLabel(
                "Protect yourself from suspicious links and scams"
        );
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 14));
        subtitle.setForeground(mutedColor);
        subtitle.setAlignmentX(Component.CENTER_ALIGNMENT);

       
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(
                new BoxLayout(headerPanel, BoxLayout.Y_AXIS)
        );
        headerPanel.setBackground(backgroundColor);

        headerPanel.add(title);
        headerPanel.add(Box.createVerticalStrut(10));
        headerPanel.add(subtitle);

      
        JPanel buttonPanel = new JPanel(new GridLayout(3, 2, 18, 18));
        buttonPanel.setBackground(backgroundColor);

      
        JButton websiteButton = createButton("Website Detection");
        JButton messageButton = createButton("Message Detection");
        JButton emailButton = createButton("Email Detection");
        JButton phoneButton = createButton("Phone Detection");
        JButton screenshotButton = createButton("Image Detection");
        JButton qrButton = createButton("QR Code Detection");

      
        buttonPanel.add(websiteButton);
        buttonPanel.add(messageButton);
        buttonPanel.add(emailButton);
        buttonPanel.add(phoneButton);
        buttonPanel.add(screenshotButton);
        buttonPanel.add(qrButton);

       
        JButton historyButton = createButton("View Scan History");

        JPanel bottomPanel = new JPanel();
        bottomPanel.setBackground(backgroundColor);
        bottomPanel.add(historyButton);

       
        websiteButton.addActionListener(e -> new WebsiteFrame());
        messageButton.addActionListener(e -> new MessageFrame());
        emailButton.addActionListener(e -> new EmailFrame());
        phoneButton.addActionListener(e -> new PhoneFrame());
        screenshotButton.addActionListener(e -> new ScreenshotFrame());
        qrButton.addActionListener(e -> new QRFrame());
        historyButton.addActionListener(e -> new HistoryFrame());

      
        mainPanel.add(headerPanel, BorderLayout.NORTH);
        mainPanel.add(buttonPanel, BorderLayout.CENTER);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

       
        setContentPane(mainPanel);

        
        setVisible(true);
    }

    
    private JButton createButton(String text) {

        JButton button = new JButton(text);

        button.setFont(new Font("SansSerif", Font.BOLD, 16));
        button.setForeground(textColor);
        button.setBackground(panelColor);
        button.setFocusPainted(false);
        button.setOpaque(true);
        button.setBorderPainted(false);
        button.setCursor(
                new Cursor(Cursor.HAND_CURSOR)
        );
        button.setBorder(
                BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(accentColor, 1),
                        BorderFactory.createEmptyBorder(15, 10, 15, 10)
                )
        );

        return button;
    }

    
    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> new HomeFrame());
    }
}
