import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JButton;
import java.awt.Font;
import java.awt.Color;

public class swing {

    public static void main(String[] args) {

        JFrame frame = new JFrame("Sreenandh V Nair");

        JLabel label = new JLabel("Hello Sreenandh");
        label.setFont(new Font("Arial", Font.BOLD, 20));

        JButton button = new JButton("Click Me");
        button.setBackground(Color.BLUE);
        button.setForeground(Color.WHITE);
        button.setOpaque(true);
        button.setBorderPainted(false);

        frame.add(label);
        frame.add(button);

        frame.setLayout(new java.awt.FlowLayout());
        frame.getContentPane().setBackground(Color.LIGHT_GRAY);

        frame.setSize(300, 200);
        frame.setVisible(true);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
}