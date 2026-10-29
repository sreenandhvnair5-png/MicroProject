
package FRAMES;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class DatabaseManager {

    private static final String DB_FOLDER = getDatabaseFolder();

    private static final String DB_URL =
            "jdbc:sqlite:" + DB_FOLDER
            + File.separator + "scans.db";

    private static boolean initialized = false;

    // Store the database in the current Windows user's
    // Local AppData folder.
    private static String getDatabaseFolder() {

        String localAppData = System.getenv("LOCALAPPDATA");

        if (localAppData != null && !localAppData.trim().isEmpty()) {
            return localAppData + File.separator + "ScamDetector";
        }

        // Fallback if LOCALAPPDATA is unavailable.
        return System.getProperty("user.home")
                + File.separator + "ScamDetector";
    }

    private static Connection openConnection() throws Exception {

        Class.forName("org.sqlite.JDBC");

        Connection con = DriverManager.getConnection(DB_URL);

        try (Statement stmt = con.createStatement()) {
            stmt.execute("PRAGMA busy_timeout = 5000");
        }

        return con;
    }

    private static synchronized void ensureInitialized()
            throws Exception {

        if (initialized) {
            return;
        }

        File folder = new File(DB_FOLDER);

        if (!folder.exists() && !folder.mkdirs()) {
            throw new Exception(
                    "Cannot create database folder: "
                    + folder.getAbsolutePath());
        }

        if (!folder.isDirectory() || !folder.canWrite()) {
            throw new Exception(
                    "Database folder is not writable: "
                    + folder.getAbsolutePath());
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

        System.out.println(
                "SQLite database ready: "
                + new File(DB_FOLDER, "scans.db").getAbsolutePath());
    }

    // Initialize the database when the application starts.

      public static void initializeDatabase() {
         try {
            ensureInitialized();
            System.out.println("SQLite database initialized successfully.");
        } catch (Exception e) {
            initialized = false;
            System.err.println(
               "WARNING: Database unavailable. Scanning will continue.");
          e.printStackTrace();
      }
    }



    public static Connection getConnection() throws Exception {

        ensureInitialized();

        return openConnection();
    }

    // Save one scan.
    public static void saveScan(
            String type,
            String content,
            String result,
            int riskScore) {

        String sql =
                "INSERT INTO scan_history "
                + "(scan_type, scanned_content, result, risk_score) "
                + "VALUES (?, ?, ?, ?)";

        try (Connection con = getConnection();
             PreparedStatement pstmt = con.prepareStatement(sql)) {

            pstmt.setString(1, type);
            pstmt.setString(2, content);
            pstmt.setString(3, result);
            pstmt.setInt(4, riskScore);

            pstmt.executeUpdate();

        } catch (Exception e) {
            System.err.println("Failed to save scan:");
            e.printStackTrace();
        }
    }

    // Retrieve all saved scans.
    public static ResultSet getAllScans(Connection con)
            throws Exception {

        String sql =
                "SELECT id, scan_type, scanned_content, "
                + "result, risk_score, scan_time "
                + "FROM scan_history ORDER BY id DESC";

        Statement stmt = con.createStatement();

        return stmt.executeQuery(sql);
    }
}
