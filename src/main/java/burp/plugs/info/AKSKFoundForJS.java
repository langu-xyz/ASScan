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
                put("AKorSK", "(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([0-9a-zA-Z\\-_=]{8,64})['\\\"]");
                //put("SecretKey", "[Ss](ecret|ECRET)_?[Kk](ey|EY)");
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
                if ((sensInfo.split(":").length == 2) & (sensInfo.split(":")[sensInfo.split(":").length-1].length() > 8)){
                    sensInfoMap.put(sensInfo, regex.getKey());
                    //前边为值，后边为类型
                }

            }
        }

        return sensInfoMap;
    }
}

/**
 *
 * Thanks https://mp.weixin.qq.com/s/SxvOu85sUJeYihLESIqsMg
 *
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