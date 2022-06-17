package burp.plugs.info;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InfoFound2JS {

    public Map<String, String> contentAnalyse(String content){

        String infoPattern = "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]+\\.[a-zA-Z]{2,}[^\"']*)|((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]+)|([a-zA-Z0-9_\\-/]+/[a-zA-Z0-9_\\-/]+\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/][^\"|']*|))|([a-zA-Z0-9_\\-]+\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']*|)))(?:\"|')";

        HashMap<String, String> infoMap = new HashMap<>();

        List<String> infoList = new ArrayList<>();

        Pattern pattern = Pattern.compile(infoPattern);
        Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            matcher.reset();
            while (matcher.find()) {
                infoList.add(matcher.group());
            }
        }
        for (String info : infoList){
            if (!(info.contains("./")|info.contains(".js"))){
                if (info.contains(".json")){
                    //前边为值，后边为类型
                    infoMap.put(info, "API");
                }else if (info.contains("://")){
                    infoMap.put(info, "URL");
                }else {
                    infoMap.put(info, "info");
                }
            }
        }

        return infoMap;
    }
}