
package FRAMES;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.File;

public class DatabaseManager {

    private static final String DB_FOLDER =
            System.getProperty("user.home") + File.separator + ".scamdetector";

    private static final String DB_URL =
            "jdbc:sqlite:" + DB_FOLDER + File.separator + "scans.db";

    // Connect to the database
    public static Connection getConnection() throws Exception {
        Class.forName("org.sqlite.JDBC");
        return DriverManager.getConnection(DB_URL);
    }

    // Create the database table if it does not exist
    public static void initializeDatabase() {
        try {
            File folder = new File(DB_FOLDER);

            if (!folder.exists()) {
                folder.mkdirs();
            }

            String sql = "CREATE TABLE IF NOT EXISTS scan_history ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "scan_type TEXT NOT NULL, "
                    + "scanned_content TEXT, "
                    + "result TEXT, "
                    + "risk_score INTEGER, "
                    + "scan_time TEXT DEFAULT "
                    + "(datetime('now','localtime'))"
                    + ")";

            try (Connection con = getConnection();
                 Statement stmt = con.createStatement()) {

                stmt.execute(sql);
            }

            System.out.println("Database initialized successfully!");

        } catch (Exception e) {
            System.out.println("Database initialization failed!");
            e.printStackTrace();
        }
    }

    // Save a scan result
    public static void saveScan(
            String type,
            String content,
            String result,
            int riskScore) {

        String sql = "INSERT INTO scan_history "
                + "(scan_type, scanned_content, result, risk_score) "
                + "VALUES (?, ?, ?, ?)";

        try (Connection con = getConnection();
             PreparedStatement pstmt = con.prepareStatement(sql)) {

            pstmt.setString(1, type);
            pstmt.setString(2, content);
            pstmt.setString(3, result);
            pstmt.setInt(4, riskScore);

            pstmt.executeUpdate();

            System.out.println("Scan saved successfully!");

        } catch (Exception e) {
            System.out.println("Failed to save scan!");
            e.printStackTrace();
        }
    }

    // Retrieve all saved scans
    public static ResultSet getAllScans(Connection con)
            throws Exception {

        String sql = "SELECT id, scan_type, scanned_content, "
                + "result, risk_score, scan_time "
                + "FROM scan_history ORDER BY id DESC";

        Statement stmt = con.createStatement();
        return stmt.executeQuery(sql);
    }
}

