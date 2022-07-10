package burp;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class BurpFuncTest {

    private static final String SQL_TABLE_CREATE = "CREATE TABLE IF NOT EXISTS ACTIVITY (LOCAL_SOURCE_IP TEXT, TARGET_URL TEXT, HTTP_METHOD TEXT, BURP_TOOL TEXT, REQUEST_RAW TEXT, SEND_DATETIME TEXT, HTTP_STATUS_CODE TEXT, RESPONSE_RAW TEXT)";
    private Connection storageConnection;
    private String url;


    void BurpFuncTest(String dbUrl) throws Exception {

        Class.forName("org.sqlite.JDBC");
        updateStoreLocation(dbUrl);
    }

    void updateStoreLocation(String dbUrl) throws Exception {
        this.url = dbUrl;
        this.storageConnection = DriverManager.getConnection(dbUrl);
        this.storageConnection.setAutoCommit(true);

        try (Statement statement = this.storageConnection.createStatement()) {
            statement.execute(SQL_TABLE_CREATE);
        }
    }


    public static void main(String[] args) throws Exception {
        String dbUrl = "jdbc:sqlite://Users/test/4-GitHub/ASCenter/EASM/db.sqlite3";

        BurpFuncTest burpFuncTest = new BurpFuncTest();

        burpFuncTest.BurpFuncTest(dbUrl);
    }
}
