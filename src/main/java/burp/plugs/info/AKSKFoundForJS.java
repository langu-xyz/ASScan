package burp.plugs.info;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.*;

public class AKSKFoundForJS {

    public Map<String, String> contentAnalyse(String content){

        //regex取自https://github.com/GerbenJavado/LinkFinder
        HashMap<String, String> regexMap = new HashMap<String, String>(){
            {
                put("AccessKey", "[Aa](ccess|CCESS)_?[Kk](ey|EY)|[Aa](ccess|CCESS)_?[sS](ecret|ECRET)|[Aa](ccess|CCESS)_?(id|ID|Id)");
                put("SecretKey", "[Ss](ecret|ECRET)_?[Kk](ey|EY)");
            }
        };
        HashMap<String, String> sensInfoMap = new HashMap<>();

        for (Map.Entry<String, String> regex : regexMap.entrySet()){
            List<String> sensInfoList = new ArrayList<>();
            Pattern pattern = Pattern.compile(regex.getValue());
            Matcher matcher = pattern.matcher(content);
            if (matcher.find()) {
                matcher.reset();
                while (matcher.find()) {
                    sensInfoList.add(matcher.group());
                }
            }
            for (String sensInfo : sensInfoList){
                sensInfoMap.put(sensInfo, regex.getKey());
                //前边为值，后边为类型
            }
        }

        return sensInfoMap;
    }
}

/**
 * https://bacde.me/post/Extract-API-Keys-From-Regex/
 *
 * "aliyun_oss_url": "[\\w-.]\\.oss.aliyuncs.com"
 * "azure_storage": "https?://[\\w-\.]\\.file.core.windows.net"
 * "access_key": "[Aa](ccess|CCESS)_?[Kk](ey|EY)|[Aa](ccess|CCESS)_?[sS](ecret|ECRET)|[Aa](ccess|CCESS)_?(id|ID|Id)"
 * "secret_key": "[Ss](ecret|ECRET)_?[Kk](ey|EY)"
 * "slack_token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"
 *
 * "slack_webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
 * "facebook_oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
 * "twitter_oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]"
 * "heroku_api": "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
 * "mailgun_api": "key-[0-9a-zA-Z]{32}"
 * "mailchamp_api": "[0-9a-f]{32}-us[0-9]{1,2}"
 * "picatic_api": "sk_live_[0-9a-z]{32}"
 * "google_oauth_id": "[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com"
 * "google_api": "AIza[0-9A-Za-z-_]{35}"
 * "google_captcha": "6L[0-9A-Za-z-_]{38}"
 * "google_oauth": "ya29\\.[0-9A-Za-z\\-_]+"
 * "amazon_aws_access_key_id": "AKIA[0-9A-Z]{16}"
 * "amazon_mws_auth_token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
 * "amazonaws_url": "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com"
 * "facebook_access_token": "EAACEdEose0cBA[0-9A-Za-z]+"
 * "mailgun_api_key": "key-[0-9a-zA-Z]{32}"
 * "twilio_api_key": "SK[0-9a-fA-F]{32}"
 * "twilio_account_sid": "AC[a-zA-Z0-9_\\-]{32}"
 * "twilio_app_sid": "AP[a-zA-Z0-9_\\-]{32}"
 * "paypal_braintree_access_token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"
 * "square_oauth_secret": "sq0csp-[ 0-9A-Za-z\\-_]{43}"
 * "square_access_token": "sqOatp-[0-9A-Za-z\\-_]{22}"
 * "stripe_standard_api": "sk_live_[0-9a-zA-Z]{24}"
 * "stripe_restricted_api": "rk_live_[0-9a-zA-Z]{24}"
 * "github_access_token": "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*"
 * "private_ssh_key": "-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY——"
 * "private_rsa_key": "-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----"
 */