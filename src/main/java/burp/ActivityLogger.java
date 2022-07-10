package burp;

import burp.utils.VulnIssue;

import java.net.InetAddress;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Handle the recording of the activities into the real storage, SQLite local DB here.
 */
public class ActivityLogger implements IExtensionStateListener {

    /**
     * SQL instructions.
     */
    private static final String SQL_TABLE_CREATE = "CREATE TABLE IF NOT EXISTS ACTIVITY (LOCAL_SOURCE_IP TEXT, TARGET_URL TEXT, HTTP_METHOD TEXT, BURP_TOOL TEXT, REQUEST_RAW TEXT, SEND_DATETIME TEXT, HTTP_STATUS_CODE TEXT, RESPONSE_RAW TEXT)";
    private static final String SQL_TABLE_INSERT = "INSERT INTO ACTIVITY (LOCAL_SOURCE_IP,TARGET_URL,HTTP_METHOD,BURP_TOOL,REQUEST_RAW,SEND_DATETIME,HTTP_STATUS_CODE,RESPONSE_RAW) VALUES(?,?,?,?,?,?,?,?)";
    private static final String SQL_COUNT_RECORDS = "SELECT COUNT(HTTP_METHOD) FROM ACTIVITY";
    private static final String SQL_TOTAL_AMOUNT_DATA_SENT = "SELECT TOTAL(LENGTH(REQUEST_RAW)) FROM ACTIVITY";
    private static final String SQL_BIGGEST_REQUEST_AMOUNT_DATA_SENT = "SELECT MAX(LENGTH(REQUEST_RAW)) FROM ACTIVITY";
    private static final String SQL_MAX_HITS_BY_SECOND = "SELECT COUNT(REQUEST_RAW) AS HITS, SEND_DATETIME FROM ACTIVITY GROUP BY SEND_DATETIME ORDER BY HITS DESC";

    private static final String SQL_ISSUES_TABLE_CREATE = "CREATE TABLE IF NOT EXISTS ISSUES (httpService TEXT, url TEXT, httpMessages TEXT, name TEXT, detail TEXT, severity TEXT)";
    private static final String SQL_ISSUES_TABLE_INSERT = "INSERT INTO ACTIVITY (httpService, url, httpMessages, name, detail, severity) VALUES(?,?,?,?,?,?)";


    /**
     * Empty string to use when response must be not be logged.
     */
    private static final String EMPTY_RESPONSE_CONTENT = "";


    /**
     * Use a single DB connection for performance and to prevent DB file locking issue at filesystem level.
     */
    private Connection storageConnection;

    /**
     * DB URL
     */
    private String url;

    /**
     * Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the activity (tool name).
     */
    private IBurpExtenderCallbacks callbacks;

    /**
     * Ref on project logger.
     */
    private Trace trace;

    /**
     * Formatter for date/time.
     */
    private DateTimeFormatter datetimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private VulnIssue vulnIssue;

    /**
     * Constructor.
     *
     * @param storeName Name of the storage that will be created (file path).
     * @param callbacks Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the activity (tool name).
     * @param trace     Ref on project logger.
     * @throws Exception If connection with the DB cannot be opened or if the DB cannot be created or if the JDBC driver cannot be loaded.
     */
    ActivityLogger(String storeName, IBurpExtenderCallbacks callbacks, Trace trace) throws Exception {
        //Load the SQLite driver
        Class.forName("org.sqlite.JDBC");
        //Affect the properties
        this.callbacks = callbacks;
        this.trace = trace;
        updateStoreLocation(storeName);
    }

    /**
     * Change the location where DB is stored.
     *
     * @param storeName Name of the storage that will be created (file path).
     * @throws Exception If connection with the DB cannot be opened or if the DB cannot be created or if the JDBC driver cannot be loaded.
     */
    void updateStoreLocation(String storeName) throws Exception {
        String newUrl = "jdbc:sqlite:" + storeName;
        this.url = newUrl;
        //Open the connection to the DB
        this.trace.writeLog("Activity information will be stored in database file '" + storeName + "'.");
        this.storageConnection = DriverManager.getConnection(newUrl);
        this.storageConnection.setAutoCommit(true);
        this.trace.writeLog("Open new connection to the storage.");
        //Create the table
        try (Statement stmt = this.storageConnection.createStatement()) {
            stmt.execute(SQL_TABLE_CREATE);
            stmt.execute(SQL_ISSUES_TABLE_CREATE);
            this.trace.writeLog("Recording table initialized.");
        }
    }

    /**
     * Save an activity event into the storage.
     *
     * @param toolFlag   A flag indicating the Burp tool that issued the request.
     *                   Burp tool flags are defined in the
     *                   <code>IBurpExtenderCallbacks</code> interface.
     * @param reqInfo    Details of the request to be processed.
     * @param reqContent Raw content of the request.
     * @throws Exception If event cannot be saved.
     */
    public void logEvent(int toolFlag, IRequestInfo reqInfo, byte[] reqContent, String statusCode, byte[] resContent) throws Exception {
        //Verify that the DB connection is still opened
        this.ensureDBState();
        //Insert the event into the storage
        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_TABLE_INSERT)) {
            stmt.setString(1, InetAddress.getLocalHost().getHostAddress());
            stmt.setString(2, reqInfo.getUrl().toString());
            stmt.setString(3, reqInfo.getMethod());
            stmt.setString(4, callbacks.getToolName(toolFlag));
            stmt.setString(5, callbacks.getHelpers().bytesToString(reqContent));
            stmt.setString(6, LocalDateTime.now().format(this.datetimeFormatter));
            stmt.setString(7, statusCode);
            stmt.setString(8, (resContent != null) ? callbacks.getHelpers().bytesToString(resContent) : EMPTY_RESPONSE_CONTENT);
            int count = stmt.executeUpdate();
            if (count != 1) {
                this.trace.writeLog("Request was not inserted, no detail available (insertion counter = " + count + ") !");
            }
        }
    }


    void issuesEvent(IScanIssue iScanIssue) throws Exception {
        this.ensureDBState();

        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_ISSUES_TABLE_INSERT)) {
            stmt.setString(1, iScanIssue.getHttpService().toString());
            stmt.setString(2, iScanIssue.getUrl().toString());
            stmt.setString(3, iScanIssue.getHttpMessages().toString());
            stmt.setString(4, iScanIssue.getIssueName());
            stmt.setString(5, iScanIssue.getIssueDetail());
            stmt.setString(6, iScanIssue.getSeverity());
            stmt.executeUpdate();
        }
    }

    /**
     * Extract and compute statistics about the DB.
     *
     * @return A VO object containing the statistics.
     * @throws Exception If computation meet and error.
     */
    DBStats getEventsStats() throws Exception {
        //Verify that the DB connection is still opened
        this.ensureDBState();
        //Get the total of the records in the activity table
        long recordsCount;
        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_COUNT_RECORDS)) {
            try (ResultSet rst = stmt.executeQuery()) {
                recordsCount = rst.getLong(1);
            }
        }
        //Get data amount if the DB is not empty
        long totalAmountDataSent = 0;
        long biggestRequestAmountDataSent = 0;
        long maxHitsBySecond = 0;
        if (recordsCount > 0) {
            //Get the total amount of data sent, we assume here that 1 character = 1 byte
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_TOTAL_AMOUNT_DATA_SENT)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    totalAmountDataSent = rst.getLong(1);
                }
            }
            //Get the amount of data sent by the biggest request, we assume here that 1 character = 1 byte
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_BIGGEST_REQUEST_AMOUNT_DATA_SENT)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    biggestRequestAmountDataSent = rst.getLong(1);
                }
            }
            //Get the maximum number of hits sent in a second
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_MAX_HITS_BY_SECOND)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    maxHitsBySecond = rst.getLong(1);
                }
            }
        }
        //Get the size of the file on the disk
        String fileLocation = this.url.replace("jdbc:sqlite:", "").trim();
        long fileSize = Paths.get(fileLocation).toFile().length();
        //Build the VO and return it
        return new DBStats(fileSize, recordsCount, totalAmountDataSent, biggestRequestAmountDataSent, maxHitsBySecond);
    }

    /**
     * Ensure the connection to the DB is valid.
     *
     * @throws Exception If connection cannot be verified or opened.
     */
    private void ensureDBState() throws Exception {
        //Verify that the DB connection is still opened
        if (this.storageConnection.isClosed()) {
            //Get new one
            this.trace.writeLog("Open new connection to the storage.");
            this.storageConnection = DriverManager.getConnection(url);
            this.storageConnection.setAutoCommit(true);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void extensionUnloaded() {
        try {
            if (this.storageConnection != null && !this.storageConnection.isClosed()) {
                this.storageConnection.close();
                this.trace.writeLog("Connection to the storage released.");
            }
        } catch (Exception e) {
            this.trace.writeLog("Cannot close the connection to the storage: " + e.getMessage());
        }
    }
}
