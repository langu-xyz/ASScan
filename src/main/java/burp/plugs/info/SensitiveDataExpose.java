package burp.plugs.info;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SensitiveDataExpose {

    public HashMap<String, String> sensitiveDataExposeFound(String response_body){

        String sensitivePhonePattern = "\"1[3-9]\\d{9}\"";

        HashMap<String, String> sensitiveDataMap = new HashMap<>();
        List<String> sensitiveDataList = new ArrayList<>();

        Pattern pattern = Pattern.compile(sensitivePhonePattern);
        Matcher matcher = pattern.matcher(response_body);

        if (matcher.find()){
            matcher.reset();
            while (matcher.find()){
                sensitiveDataList.add(matcher.group());
            }
        }

        for (String sensitiveData : sensitiveDataList){
            sensitiveDataMap.put(sensitiveData, "PhoneNum");
        }

        return sensitiveDataMap;
    }
}
