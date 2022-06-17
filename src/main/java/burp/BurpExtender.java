package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.List;

import burp.plugs.info.InfoFound2JS;
import burp.plugs.info.SensitiveDataExpose;
import burp.plugs.info.WeakSpotParam;
import burp.utils.ScanItem;
import burp.utils.VulnIssue;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IExtensionHelpers iExtensionHelpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {

        this.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        this.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        this.iExtensionHelpers = iBurpExtenderCallbacks.getHelpers();

        iBurpExtenderCallbacks.registerScannerCheck(this);


        this.stdout.println("Hello, Attack Surface Scan");
        this.stdout.println("The Real Passive Scan, It's like a submarine.");
        this.stdout.println("Version 0.01");
        this.stdout.println("Author: langu.xyz");
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

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        IRequestInfo iRequestInfo = this.iExtensionHelpers.analyzeRequest(iHttpRequestResponse);
        List<IScanIssue> issues = responseFuzz(iHttpRequestResponse, iRequestInfo);
        List<IScanIssue> iScanIssues = new ArrayList<>(issues);
        return iScanIssues;
    }

    private List<IScanIssue> responseFuzz(IHttpRequestResponse iHttpRequestResponse, IRequestInfo iRequestInfo) {
        Map<String, ScanItem> targetMap = new HashMap<>();

        URL baseHttpRequestUrl = iRequestInfo.getUrl();

        String requestUrl = baseHttpRequestUrl.getProtocol()
                + "://" + baseHttpRequestUrl.getHost()
                + ":" + baseHttpRequestUrl.getPort()
                + baseHttpRequestUrl.getPath();

        targetMap.put(requestUrl, new ScanItem(baseHttpRequestUrl, iHttpRequestResponse));

        List<IScanIssue> issues = riskFound(targetMap, iRequestInfo);

        return issues;
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

    private String getResponseBody(IResponseInfo iResponseInfo, ScanItem scanItem){
        int bodyOffset = iResponseInfo.getBodyOffset();
        byte[] byteResponse = scanItem.iHttpRequestResponse.getResponse();
        byte[] byteBody = Arrays.copyOfRange(byteResponse, bodyOffset, byteResponse.length);
        String responseBody = new String(byteBody);
        return responseBody;
    }

    private List<IScanIssue> riskFound(Map<String, ScanItem> targetMap, IRequestInfo iRequestInfo) {
        List<IScanIssue> iScanIssues = new ArrayList<>();
        for (Map.Entry<String, ScanItem> domainItem :
                targetMap.entrySet()) {
            ScanItem scanItem = domainItem.getValue();
            String requestUrl = domainItem.getKey();
            IResponseInfo iResponseInfo = this.iExtensionHelpers.analyzeResponse(scanItem.iHttpRequestResponse.getResponse());

            stdout.println(iResponseInfo.getStatedMimeType());

            //Risk expose point found for API.
            if (iResponseInfo.getInferredMimeType().equals("HTML")|iResponseInfo.getInferredMimeType().equals("text")|iResponseInfo.getInferredMimeType().equals("JSON")){
                this.stdout.println("API URl:" +  requestUrl);
                this.stdout.println("API Params:" + iRequestInfo.getParameters());
                //[burp.i8k@162e5bd, burp.i8k@fb51c94, burp.i8k@3029e13b, burp.i8k@771446a0, burp.i8k@614d1af2, burp.i8k@46bbebf3, burp.i8k@3964fa26]
                //这里需要加入一段判断是否有可遍历参数的逻辑
                if (!iRequestInfo.getParameters().isEmpty()){
                    for (IParameter iParameter:iRequestInfo.getParameters() ){
                        if (iParameter.getType() != 2){
                            //=2 不在cookie中的参数
                            //=0 URL =6 JSON =1 body =3 xml =5 PARAM_MULTIPART_ATTR =4 PARAM_XML_ATTR
                            this.stdout.println("param name:" +  iParameter.getName());
                            this.stdout.println("param value:" +  iParameter.getValue());
                            this.stdout.println("param Type:" +  iParameter.getType());
                            //传入param name和param value

                            WeakSpotParam weakSpotParam = new WeakSpotParam();
                            HashMap<String, String> weakSpotParamResult = weakSpotParam.paramAnalyse(iParameter.getName(), iParameter.getValue());

                            iScanIssues.add(new VulnIssue(scanItem.iHttpRequestResponse.getHttpService(), scanItem.url, new IHttpRequestResponse[]{scanItem.iHttpRequestResponse}, weakSpotParamResult.get("name") + ":" + weakSpotParamResult.get("value") + ":" + weakSpotParamResult.get("as"), weakSpotParamResult.get("as"), "Medium"));

                        }
                    }
                }

                //Sensitive Data in Response
                String responseBody = getResponseBody(iResponseInfo, scanItem);

                SensitiveDataExpose sensitiveDataExpose = new SensitiveDataExpose();
                HashMap<String, String> sensitiveDataMap = sensitiveDataExpose.sensitiveDataExposeFound(responseBody);

                if (!sensitiveDataMap.isEmpty()) {
                    for (Map.Entry<String, String> sensitiveData : sensitiveDataMap.entrySet()) {
                        iScanIssues.add(new VulnIssue(scanItem.iHttpRequestResponse.getHttpService(), scanItem.url, new IHttpRequestResponse[]{scanItem.iHttpRequestResponse}, sensitiveData.getValue() + ":" + sensitiveData.getKey(), sensitiveData.getValue() + ":" + sensitiveData.getKey(), "Medium"));
                    }
                } else {
                    return null;
                }

            }

            //JavaScript relational
            //if (domainItem.getKey().endsWith("js")) {
            //这里没有排除掉通用的js，例如jquery
            if (iResponseInfo.getInferredMimeType().equals("script")&!scanItem.url.toString().contains("jquery")) {

                this.stdout.println("JS URL：" + domainItem);
                String responseBody = getResponseBody(iResponseInfo, scanItem);
                String getReferer = getHeaders(scanItem.iHttpRequestResponse).get("Referer");

                // byte[] byteRequest = scanItem.iHttpRequestResponse.getRequest();
                //this.stdout.println("iResponseInfo：" + iResponseInfo.getStatedMimeType());
                //this.stdout.println("iResponseInfo：" + iResponseInfo.getBodyOffset());

                //POC1 JavaScript文件中的API识别
                InfoFound2JS infoFound2JS = new InfoFound2JS();
                Map<String, String> APIList = infoFound2JS.contentAnalyse(responseBody);
                //stderr.println(sensInfoList.toString());
                if (!APIList.isEmpty()) {
                    for (Map.Entry<String, String> API : APIList.entrySet()) {
                        iScanIssues.add(new VulnIssue(scanItem.iHttpRequestResponse.getHttpService(), scanItem.url, new IHttpRequestResponse[]{scanItem.iHttpRequestResponse}, API.getValue() + ":" + API.getKey(), "Referer:" + getReferer, "Information"));
                    }
                } else {
                    return null;
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
}
