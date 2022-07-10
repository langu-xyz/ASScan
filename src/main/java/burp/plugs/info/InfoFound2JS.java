package burp.plugs.info;

import java.util.*;
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
            if (infoTypeExclude(info)){
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

    private Boolean infoTypeExclude(String info){
        List<String> EXCLUDE_LIST = Arrays.asList("./",".js",".swf",".mp3" ,".html",".htm",".png",".ase",".art",".bmp",".blp",".cd5",".cit",".cpt",".cr2",".cut",".dds",".dib",".djvu",".egt",".exif",".gif",".gpl",".grf",".icns",".ico",".iff",".jng",".jpeg",".jpg",".jfif",".jp2",".jps",".lbm",".max",".miff",".mng",".msp",".nitf",".ota",".pbm",".pc1",".pc2",".pc3",".pcf",".pcx",".pdn",".pgm",".PI1",".PI2",".PI3",".pict",".pct",".pnm",".pns",".ppm",".psb",".psd",".pdd",".psp",".px",".pxm",".pxr",".qfx",".raw",".rle",".sct",".sgi",".rgb",".int",".bw",".tga",".tiff",".tif",".vtf",".xbm",".xcf",".xpm",".3dv",".amf",".ai",".awg",".cgm",".cdr",".cmx",".dxf",".e2d",".egt",".eps",".fs",".gbr",".odg",".svg",".stl",".vrml",".x3d",".sxd",".v2d",".vnd",".wmf",".emf",".art",".xar",".png",".webp",".jxr",".hdp",".wdp",".cur",".ecw",".iff",".lbm",".liff",".nrrd",".pam",".pcx",".pgf",".sgi",".rgb",".rgba",".bw",".int",".inta",".sid",".ras",".sun",".tga");
        for (String exclude : EXCLUDE_LIST){
            if (info.contains(exclude)){
                return false;
            }
        }
        return true;
    }
}