package FRAMES;

import javax.swing.*;

public class HistoryFrame extends JFrame {

    public HistoryFrame() {
        setTitle("Scan History");
        setSize(700, 400);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        JLabel heading = new JLabel("SCAN HISTORY");
        heading.setHorizontalAlignment(SwingConstants.CENTER);

        String[] columns = {"Type", "Input", "Result", "Risk Score"};

        String[][] data = {
            {"Website", "example.com", "NOT ANALYZED", "--"}
        };

        JTable historyTable = new JTable(data, columns);

        JScrollPane scrollPane = new JScrollPane(historyTable);

        add(heading, "North");
        add(scrollPane, "Center");

        setVisible(true);
    }

    public static void main(String[] args) {
        new HistoryFrame();
    }
}
