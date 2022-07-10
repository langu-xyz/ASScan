package burp;

import burp.plugs.info.AKSKFoundForJS;
import burp.plugs.info.InfoFound2JS;
import burp.plugs.info.SensitiveDataExpose;
import burp.plugs.info.WeakSpotParam;
import burp.utils.VulnIssue;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.io.File;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;


public class BurpExtender implements IBurpExtender, IScannerCheck   {

    private IExtensionHelpers iExtensionHelpers;
    private PrintWriter stdout;
    private PrintWriter stderr;


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {


        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.iExtensionHelpers = callbacks.getHelpers();

        callbacks.registerScannerCheck(this);


        this.stdout.println("Hello, Attack Surface Scan");
        this.stdout.println("The Real Passive Scan, It's like a submarine.");
        this.stdout.println("Version 0.01");
        this.stdout.println("Author: langu_xyz");
        this.stdout.println("===Functions====");
        this.stdout.println("1. API、SubDomain or other information found for JavaScript file.");
        this.stdout.println("2. AccessKey/SecretKey found for JavaScript file.");
        this.stdout.println("3. Dom Vulnerability Insertion point found for JavaScript file.");
        this.stdout.println("4. Broken Authentication Insertion point found for API.");
        this.stdout.println("5. Sensitive Data expose point found for API.");
        this.stdout.println("6. XXE or SSRF Insertion point found for API.");
        this.stdout.println("8. Website's fingerprint found for requests.");
        this.stdout.println("9. Not to stay up ...");
        this.stdout.println("===============");

        this.stdout.println("Loading ... ... ...");
        this.stdout.println("Loaded");
        this.stdout.println("Enjoy your hacking life.");

        this.stderr.println("Hello, No Error");


        ConfigMenu configMenu = null;
        String extensionName = "ASScan v1.0";
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        try {
            callbacks.setExtensionName(extensionName);
            Trace trace = new Trace(callbacks);
            String defaultStoreFileName = new File(System.getProperty("user.home"), extensionName + ".db").getAbsolutePath().replaceAll("\\\\", "/");
            String customStoreFileName = callbacks.loadExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
            if (customStoreFileName == null || !Files.exists(Paths.get(customStoreFileName))) {
                if(customStoreFileName != null){
                    callbacks.issueAlert("Default store file used because the previously stored DB file do not exist anymore ('" + customStoreFileName + "')");
                }
                customStoreFileName = defaultStoreFileName;
            }
            boolean isLoggingPaused = Boolean.parseBoolean(callbacks.loadExtensionSetting(ConfigMenu.PAUSE_LOGGING_CFG_KEY));
            if (!isLoggingPaused) {
                Object[] options = {"Keep the DB file", "Change the DB file", "Pause the logging"};
                String msg = "Continue to log events into the following database file?\n\r" + customStoreFileName;
                int loggingQuestionReply = JOptionPane.showOptionDialog(burpFrame, msg, extensionName, JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, null);
                if (loggingQuestionReply == JOptionPane.YES_OPTION) {
                    callbacks.saveExtensionSetting(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE.toString());
                    callbacks.issueAlert("Logging is enabled.");
                }
                if (loggingQuestionReply == JOptionPane.NO_OPTION) {
                    JFileChooser customStoreFileNameFileChooser = Utilities.createDBFileChooser();
                    int dbFileSelectionReply = customStoreFileNameFileChooser.showDialog(burpFrame, "Use");
                    if (dbFileSelectionReply == JFileChooser.APPROVE_OPTION) {
                        customStoreFileName = customStoreFileNameFileChooser.getSelectedFile().getAbsolutePath().replaceAll("\\\\", "/");
                    } else {
                        JOptionPane.showMessageDialog(burpFrame, "The following database file will continue to be used:\n\r" + customStoreFileName, extensionName, JOptionPane.INFORMATION_MESSAGE);
                    }
                    callbacks.saveExtensionSetting(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE.toString());
                    callbacks.issueAlert("Logging is enabled.");
                }
                if (loggingQuestionReply == JOptionPane.CANCEL_OPTION) {
                    callbacks.saveExtensionSetting(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.TRUE.toString());
                    callbacks.issueAlert("Logging is paused.");
                }
                callbacks.saveExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY, customStoreFileName);
            } else {
                callbacks.issueAlert("Logging is paused.");
            }
            ActivityLogger activityLogger = new ActivityLogger(customStoreFileName, callbacks, trace);
            ActivityHttpListener activityHttpListener = new ActivityHttpListener(activityLogger, trace, callbacks);
            configMenu = new ConfigMenu(callbacks, trace, activityLogger);
            SwingUtilities.invokeLater(configMenu);
            callbacks.registerHttpListener(activityHttpListener);
            callbacks.registerExtensionStateListener(activityLogger);
            callbacks.registerExtensionStateListener(configMenu);
        } catch (Exception e) {
            String errMsg = "Cannot start the extension due to the following reason:\n\r" + e.getMessage();
            if (configMenu != null) {
                configMenu.extensionUnloaded();
            }
            callbacks.issueAlert(errMsg);
            JOptionPane.showMessageDialog(burpFrame, errMsg, extensionName, JOptionPane.ERROR_MESSAGE);
        }
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        List<IScanIssue> issues = httpRequestResponseFuzz(iHttpRequestResponse);
        List<IScanIssue> iScanIssues = new ArrayList<>(issues);
        return iScanIssues;
    }

    private List<IScanIssue> httpRequestResponseFuzz(IHttpRequestResponse iHttpRequestResponse){
        List<IScanIssue> iScanIssues = new ArrayList<>();

        IRequestInfo iRequestInfo = iExtensionHelpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo iResponseInfo = iExtensionHelpers.analyzeResponse(iHttpRequestResponse.getResponse());

        //request
        //URL
        URL baseHttpRequestUrl = iRequestInfo.getUrl();
        String requestUrl = baseHttpRequestUrl.getProtocol()
                + "://" + baseHttpRequestUrl.getHost()
                + ":" + baseHttpRequestUrl.getPort()
                + baseHttpRequestUrl.getPath();
        //referer
        String getReferer = getHeaders(iHttpRequestResponse).get("Referer");


        //response
        //ret code
        String statusCode = String.valueOf(iResponseInfo.getStatusCode());
        String responseBody = getResponseBody(iResponseInfo, iHttpRequestResponse);



        //加载plugs部分
        //处理js文件部分
        //被动扫描：识别js文件中的有效信息、AKSK
        if (iResponseInfo.getInferredMimeType().equals("script") & !requestUrl.contains("jquery")) {
            this.stdout.println("scan:" + requestUrl);
            InfoFound2JS infoFound2JS = new InfoFound2JS();
            AKSKFoundForJS akskFoundForJS = new AKSKFoundForJS();
            Map<String, String> APIList = infoFound2JS.contentAnalyse(responseBody);
            Map<String, String> AKSKList = akskFoundForJS.contentAnalyse(responseBody);
            this.stdout.println(APIList);
            this.stdout.println(AKSKList);
            if (!APIList.isEmpty()) {
                for (Map.Entry<String, String> API : APIList.entrySet()) {
                    VulnIssue vulnIssue = new VulnIssue(iHttpRequestResponse.getHttpService(), baseHttpRequestUrl, new IHttpRequestResponse[]{iHttpRequestResponse}, API.getValue() + ":" + API.getKey(), "Referer:" + getReferer, "Information");
                    iScanIssues.add(vulnIssue);

                }
            }
            if (!AKSKList.isEmpty()) {
                for (Map.Entry<String, String> AKorSK : AKSKList.entrySet()) {
                    VulnIssue vulnIssue = new VulnIssue(iHttpRequestResponse.getHttpService(), baseHttpRequestUrl, new IHttpRequestResponse[]{iHttpRequestResponse}, AKorSK.getValue() + ":" + AKorSK.getKey(), "Referer:" + getReferer, "High");
                    iScanIssues.add(vulnIssue);

                }
            }
        }


        if (iResponseInfo.getInferredMimeType().equals("HTML")|iResponseInfo.getInferredMimeType().equals("text")|iResponseInfo.getInferredMimeType().equals("JSON")) {
            this.stdout.println("API URl:" + requestUrl);
            this.stdout.println("API Params:" + iRequestInfo.getParameters());

            //被动扫描：识别请求中的弱点参数
            if (!iRequestInfo.getParameters().isEmpty()){
                for (IParameter iParameter:iRequestInfo.getParameters() ){
                    if (iParameter.getType() != 2){
                        //!=2 不在cookie中的参数
                        //=0 URL =6 JSON =1 body =3 xml =5 PARAM_MULTIPART_ATTR =4 PARAM_XML_ATTR
                        this.stdout.println("param name:" +  iParameter.getName());
                        this.stdout.println("param value:" +  iParameter.getValue());
                        this.stdout.println("param Type:" +  iParameter.getType());
                        //传入param name和param value

                        WeakSpotParam weakSpotParam = new WeakSpotParam();
                        HashMap<String, String> weakSpotParamResult = weakSpotParam.paramAnalyse(iParameter.getName(), iParameter.getValue());

                        iScanIssues.add(new VulnIssue(iHttpRequestResponse.getHttpService(), baseHttpRequestUrl, new IHttpRequestResponse[]{iHttpRequestResponse}, weakSpotParamResult.get("name") + ":" + weakSpotParamResult.get("value") + ":" + weakSpotParamResult.get("as"), weakSpotParamResult.get("as"), "Medium"));
                    }
                }
            }

            //被动扫描：识别响应值中的敏感数据
            SensitiveDataExpose sensitiveDataExpose = new SensitiveDataExpose();
            HashMap<String, String> sensitiveDataMap = sensitiveDataExpose.sensitiveDataExposeFound(responseBody);
            if (!sensitiveDataMap.isEmpty()) {
                for (Map.Entry<String, String> sensitiveData : sensitiveDataMap.entrySet()) {
                    iScanIssues.add(new VulnIssue(iHttpRequestResponse.getHttpService(), baseHttpRequestUrl, new IHttpRequestResponse[]{iHttpRequestResponse}, sensitiveData.getValue() + ":" + sensitiveData.getKey(), sensitiveData.getValue() + ":" + sensitiveData.getKey(), "Medium"));

                }
            }
        }

        return iScanIssues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    private Map<String, String> getHeaders(IHttpRequestResponse iHttpRequestResponse){
        Map<String, String> headers = new HashMap<>();
        IRequestInfo iRequestInfo = iExtensionHelpers.analyzeRequest(iHttpRequestResponse);
        List<String> headerList = iRequestInfo.getHeaders();
        for (String header: headerList){
            if (header.startsWith("GET") || header.startsWith("POST")) {
                continue;
            } else {
                String[] headerValue = header.split(":", 2);
                headers.put(headerValue[0], headerValue[1].trim());
            }
        }
        return headers;
    }

    private String getResponseBody(IResponseInfo iResponseInfo,  IHttpRequestResponse iHttpRequestResponse){
        int bodyOffset = iResponseInfo.getBodyOffset();
        byte[] byteResponse = iHttpRequestResponse.getResponse();
        byte[] byteBody = Arrays.copyOfRange(byteResponse, bodyOffset, byteResponse.length);
        String responseBody = new String(byteBody);
        return responseBody;
    }


}