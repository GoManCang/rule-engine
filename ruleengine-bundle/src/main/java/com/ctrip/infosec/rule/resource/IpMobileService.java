package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import org.apache.commons.lang.Validate;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 2015/8/19.
 * 根据凯安的服务判断ip，mobile的风险分数
 * http://api.bigsec.com/checkvip/
 *  0 ~ 20分 无风险
    20 ~ 50分 低风险
    50 ~ 80 分 中风险
    80 ~ 100 分 高风险
 */
public class IpMobileService {
    private static int timeout = 100;//100ms
    private static URIBuilder urlBuilder = new URIBuilder();
    private static Logger logger = LoggerFactory.getLogger(IpMobileService.class);

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
            throw new IllegalArgumentException("ip和mobile都为空");
        }
        beforeInvoke();
        Map<String,String> result = new HashMap<>();
        try {
            String responseTxt = "";
            urlBuilder.setParameter("mobile",mobile);
            urlBuilder.setParameter("ip",ip);
            URI uri = urlBuilder.build();
            responseTxt = Request.Get(uri).connectTimeout(timeout).socketTimeout(timeout).execute().
                    returnContent().asString();
            Map newResult = Utils.JSON.parseObject(responseTxt, Map.class);
            if(newResult != null && newResult.size()>0)
            {
                Map scoreResult = (Map)newResult.get("result");
                if(scoreResult != null && scoreResult.size()>=2)
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
            logger.warn(Contexts.getLogPrefix() + "invoke IpMobileService.query fault.", ex);
            TraceLogger.traceLog("执行IpMobileService异常: " + ex.toString());
        } finally {
            afterInvoke("IpMobileService.query");
        }
        return result;
    }
}
