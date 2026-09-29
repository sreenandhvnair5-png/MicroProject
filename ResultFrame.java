import javax.swing.*;
public class ResultFrame extends JFrame {
 public ResultFrame() {
 setTitle("Scam Detection Result");
 setSize(600, 400);
 setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
 setLocationRelativeTo(null);
 JLabel heading = new JLabel("SCAN RESULT");
 heading.setHorizontalAlignment(SwingConstants.CENTER);
 JLabel resultLabel = new JLabel("Result: NOT ANALYZED");
 JLabel riskLabel = new JLabel("Risk Score: --");
 JTextArea reasonArea = new JTextArea("Reasons will be displayed here.");
 JButton closeButton = new JButton("CLOSE");
 add(heading, "North");
 add(resultLabel, "West");
 add(riskLabel, "Center");
 add(reasonArea, "East");
 add(closeButton, "South");
 setVisible(true);
 }
 public static void main(String[] args) {
 new ResultFrame();
 }
}
