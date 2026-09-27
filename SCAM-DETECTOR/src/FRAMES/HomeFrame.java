package FRAMES;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.SwingConstants;

public class HomeFrame extends JFrame {

    public HomeFrame() {

        setTitle("Scam Detection System");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel title = new JLabel("SCAM DETECTION SYSTEM");
        title.setHorizontalAlignment(SwingConstants.CENTER);

        add(title);

        setVisible(true);
    }

    public static void main(String[] args) {
        new HomeFrame();
    }
}