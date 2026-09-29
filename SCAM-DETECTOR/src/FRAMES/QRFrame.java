import javax.swing.*;
import java.awt.BorderLayout;
public class QRFrame extends JFrame {
 public QRFrame() {
 setTitle("QR Scam Detection");
 setSize(600, 400);
 setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
 setLocationRelativeTo(null);
 JLabel heading = new JLabel("QR CODE SCAM DETECTION");
 heading.setHorizontalAlignment(SwingConstants.CENTER);
 JButton uploadButton = new JButton("UPLOAD QR IMAGE");
 JButton scanButton = new JButton("SCAN");
 add(heading, BorderLayout.NORTH);
 add(uploadButton, BorderLayout.CENTER);
 add(scanButton, BorderLayout.SOUTH);
 setVisible(true);
 }
 public static void main(String[] args) {
 new QRFrame();
 }
}
