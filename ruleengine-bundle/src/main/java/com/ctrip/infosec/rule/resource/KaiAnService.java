package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import org.apache.http.HttpHost;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 2015/8/19.
 * 凯安服务器是电信的
 * 根据凯安的服务判断ip，mobile的风险分数
 * http://api.bigsec.com/checkvip/
 *  0 ~ 20分 无风险
    20 ~ 50分 低风险
    50 ~ 80 分 中风险
    80 ~ 100 分 高风险
   这个服务在userProfile里面提供了
 */
@Deprecated
public class KaiAnService {
    private static int timeout = 300;//300ms
    private static URIBuilder urlBuilder = new URIBuilder();
    private static Logger logger = LoggerFactory.getLogger(KaiAnService.class);
    private static HttpHost httpHost = new HttpHost("proxy2.sh2.ctripcorp.com",8080,"http");//金桥机房生产环境使用代理

    static{
        urlBuilder.setScheme("http");
        urlBuilder.setHost("api.bigsec.com");
        urlBuilder.setPath("/checkvip");
        urlBuilder.addParameter("qtype","mix");
        urlBuilder.addParameter("auth","ace0680f497ad180");
    }

    /**
     * 返回从凯安获取的分数
     * @param ip
     * @param mobile
     * @return  {"ipScore":"81.3","mobileScore":"54.0"}
     */
    public static  Map<String,String> query(String ip,String mobile){
        if ((ip == null || ip.length() == 0)&&(mobile == null || mobile.length() == 0)) {
            logger.warn("ip和mobile都为空");
            return new HashMap<>();
        }
        beforeInvoke();
        Map<String,String> result = new HashMap<>();
        try {
            String responseTxt = "";
            urlBuilder.setParameter("mobile",mobile);
            urlBuilder.setParameter("ip",ip);
            URI uri = urlBuilder.build();
            responseTxt = Request.Get(uri).viaProxy(httpHost).connectTimeout(200).socketTimeout(timeout).execute().
                    returnContent().asString();
            Map newResult = Utils.JSON.parseObject(responseTxt, Map.class);
            if(newResult != null && newResult.size()>0)
            {
                Map scoreResult = (Map)newResult.get("result");
                if(scoreResult != null)
                {
                    Map ipScore = (Map) scoreResult.get("ip");
                    Map mobileScore = (Map) scoreResult.get("mobile");
                    if(ipScore != null && mobileScore != null)
                    {
                        result.put("ipScore",ipScore.get("score") == null ?"":ipScore.get("score").toString());
                        result.put("mobileScore",ipScore.get("score") == null ?"":mobileScore.get("score").toString());
                    }
                }
            }
        }catch (Exception ex) {
            fault();
            logger.warn(Contexts.getLogPrefix() + "invoke KaiAnService.query fault.", ex);
            TraceLogger.traceLog("执行KaiAnService异常: " + ex.toString());
        } finally {
            afterInvoke("KaiAnService.query");
        }
        return result;
    }
}
