
package FRAMES;

public class DatabaseTest {

    public static void main(String[] args) {

        DatabaseManager.initializeDatabase();

        DatabaseManager.saveScan(
                "Website",
                "example.com",
                "NOT ANALYZED",
                0
        );
    }
}

