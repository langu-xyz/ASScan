package burp.plugs.info;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class WeakSpotParam {

    private final List<String> SSRF_KEY = Arrays.asList("token", "redirecturl","redirect_url", "parse","u","f","query","dest","redirect","uri","path","continue","url","window","next","data","reference","site","html","val","validate","domain","callback","return","page","view","dir","show","file","document","folder","root","path","pg","style","php_path","doc","feed","host","port","to","out");
    private final List<String> IDOR_KEY = Arrays.asList("id"); //待扩展

    public HashMap<String, String> paramAnalyse(String name, String value){
        //{'name':'', value:'','as':['xss', 'ssrf', 'idor]}
        HashMap<String, String> result = new HashMap<>();
        result.put("name", name);
        result.put("value", value);

        List<String> as = new ArrayList();

        String nameToLower = name.toLowerCase();

        if (SSRF_KEY.contains(nameToLower)){
            as.add("SSRF");
        }
        if (IDOR_KEY.contains(nameToLower)){
            as.add("IDOR");
        }

        if (!as.isEmpty()){
            result.put("as", String.valueOf(as));
        }

        return result;
    }

    private String valueType(String value){
        return "test";
    }
}
