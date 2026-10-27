package FRAMES;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class DatabaseManager {

    private static final String DB_FOLDER =
            System.getProperty("user.home")
            + File.separator + ".scamdetector";

    private static final String DB_URL =
            "jdbc:sqlite:" + DB_FOLDER
            + File.separator + "scans.db";

    private static boolean initialized = false;

    // Open a raw connection after the SQLite driver is loaded.
    private static Connection openConnection() throws Exception {
        Class.forName("org.sqlite.JDBC");
        return DriverManager.getConnection(DB_URL);
    }

    // Initialize the database only once, safely across threads.
    private static synchronized void ensureInitialized()
            throws Exception {

        if (initialized) {
            return;
        }

        File folder = new File(DB_FOLDER);

        if (!folder.exists() && !folder.mkdirs()) {
            throw new Exception(
                    "Could not create the database folder.");
        }

        if (!folder.isDirectory()) {
            throw new Exception(
                    "The database path is not a folder.");
        }

        try (Connection con = openConnection();
             Statement stmt = con.createStatement()) {

            stmt.execute(
                    "CREATE TABLE IF NOT EXISTS scan_history ("
                    + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "scan_type TEXT NOT NULL, "
                    + "scanned_content TEXT, "
                    + "result TEXT, "
                    + "risk_score INTEGER, "
                    + "scan_time TEXT DEFAULT "
                    + "(datetime('now','localtime'))"
                    + ")"
            );
        }

        initialized = true;
    }

    // Call this at application startup.
    public static void initializeDatabase() {
        try {
            ensureInitialized();
            System.out.println(
                    "Database initialized successfully.");
        } catch (Exception e) {
            initialized = false;
            System.err.println(
                    "Database initialization failed: "
                    + e.getMessage());
        }
    }

    // Every connection ensures initialization first.
    public static Connection getConnection() throws Exception {
        ensureInitialized();
        return openConnection();
    }

    // Save a scan result.
    public static void saveScan(
            String type,
            String content,
            String result,
            int riskScore) {

        String sql = "INSERT INTO scan_history "
                + "(scan_type, scanned_content, result, risk_score) "
                + "VALUES (?, ?, ?, ?)";

        try (Connection con = getConnection();
             PreparedStatement pstmt =
                     con.prepareStatement(sql)) {

            pstmt.setString(1, type);
            pstmt.setString(2, content);
            pstmt.setString(3, result);
            pstmt.setInt(4, riskScore);

            pstmt.executeUpdate();

        } catch (Exception e) {
            System.err.println(
                    "Failed to save scan: " + e.getMessage());
        }
    }

    // Retrieve all saved scans.
    // Close the ResultSet and its Connection after use.
    public static ResultSet getAllScans(Connection con)
            throws Exception {

        String sql = "SELECT id, scan_type, scanned_content, "
                + "result, risk_score, scan_time "
                + "FROM scan_history ORDER BY id DESC";

        Statement stmt = con.createStatement();
        return stmt.executeQuery(sql);
    }
}