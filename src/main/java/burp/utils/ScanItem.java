package burp.utils;

import burp.IHttpRequestResponse;
import burp.IParameter;

import java.net.URL;

public class ScanItem {

    public ScanItem(IParameter iParameter, IHttpRequestResponse iHttpRequestResponse) {
        this.iParameter = iParameter;
        this.iHttpRequestResponse = iHttpRequestResponse;
    }

    public ScanItem(URL url, IHttpRequestResponse iHttpRequestResponse) {
        this.url = url;
        this.iHttpRequestResponse = iHttpRequestResponse;
    }

    public ScanItem(String headerName, IHttpRequestResponse iHttpRequestResponse) {
        this.iIsHeader = true;
        this.iHeaderName = headerName;
        this.iHttpRequestResponse = iHttpRequestResponse;
    }


    public String iHeaderName;
    public boolean iIsHeader;
    public IParameter iParameter;
    public IHttpRequestResponse iHttpRequestResponse;
    public URL url;
}
