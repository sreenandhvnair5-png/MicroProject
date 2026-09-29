package FRAMES;
import javax.swing.*;
import java.awt.BorderLayout;
public class ScreenshotFrame extends JFrame {
 public ScreenshotFrame() {
 setTitle("Screenshot Scam Detection");
 setSize(600, 400);
 setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
 setLocationRelativeTo(null);
 JLabel heading = new JLabel("SCREENSHOT SCAM DETECTION");
 heading.setHorizontalAlignment(SwingConstants.CENTER);
 JButton uploadButton = new JButton("UPLOAD SCREENSHOT");
 JButton scanButton = new JButton("SCAN");
 add(heading, BorderLayout.NORTH);
 add(uploadButton, BorderLayout.CENTER);
 add(scanButton, BorderLayout.SOUTH);
 setVisible(true);
 }
 public static void main(String[] args) {
 new ScreenshotFrame();
 }
}
