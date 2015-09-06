package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.redis.CacheProviderFactory;
import credis.java.client.CacheProvider;
import org.apache.http.HttpHost;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 15-9-6.
 * 同盾服务器是双线的
 */
public class TongDunService {
    private static Logger logger = LoggerFactory.getLogger(TongDunService.class);
    private static int cacheExpireTime = 7*24*3600;//在redis存放7天
    private static final String cacheKeyPrefix = "ResourceCache__TongDun__";
    private static final String clusterName = "CounterServer_03";
    private static URIBuilder urlBuilder = new URIBuilder();
    private static HttpHost httpHost = new HttpHost("proxy2.sh2.ctripcorp.com",8080,"http");//金桥机房生产环境使用代理

    static{
        urlBuilder.setScheme("https");
        urlBuilder.setHost("api.fraudmetrix.cn");
        urlBuilder.setPath("/riskService");
        urlBuilder.setParameter("partner_code","ctrip");
        urlBuilder.setParameter("secret_key","daf74b287beb43a8a11f29b1ad31f570");
    }
    private static String buildCacheKey(String ip,String mobile) {
        StringBuilder builder = new StringBuilder(cacheKeyPrefix);
        builder.append(ip);
        builder.append(mobile);
        return builder.toString();
    }

    /**
     * 交易事件
     * @param ip
     * @param mobile
     * @return
     */
    public static String queryT(String ip,String mobile)
    {
        String score = "";
        beforeInvoke();
        try {
            // Cache
            CacheProvider cache = CacheProviderFactory.getCacheProvider(clusterName);
            String cacheKey = buildCacheKey(ip,mobile);
            String cachedResult = cache.get(cacheKey);
            if (cachedResult != null) {
                return cachedResult;
            }

            urlBuilder.setParameter("event_id","trade_web");//区分是交易还是注册
            //ip mobile
            urlBuilder.setParameter("ip_address",ip);
            urlBuilder.setParameter("account_mobile",mobile);

            String response = Request.Get(urlBuilder.build()).viaProxy(httpHost).connectTimeout(200).socketTimeout(500).execute().returnContent().asString();//连接200 执行300
            Map result = Utils.JSON.parseObject(response, Map.class);

            if(result != null && result.get("success").toString().toLowerCase().equals("true"))
            {
                score = result.get("final_score").toString();
                // Cache
                if (!score.isEmpty()) {
                    cache.set(cacheKey, score);
                    cache.expire(cacheKey, cacheExpireTime);
                }
            }
        }catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke TongDunService.queryT fault.", ex);
            TraceLogger.traceLog("执行invoke TongDunService.queryT异常: " + ex.toString());
        } finally {
            afterInvoke("TongDunService.queryT");
        }
        return score;
    }

    /**
     * 注册事件
     * @param ip
     * @param mobile
     * @return
     */
    public static String queryR(String ip,String mobile)
    {
        String score = "";
        beforeInvoke();
        try {
            // Cache
            CacheProvider cache = CacheProviderFactory.getCacheProvider(clusterName);
            String cacheKey = buildCacheKey(ip,mobile);
            String cachedResult = cache.get(cacheKey);
            if (cachedResult != null) {
                return cachedResult;
            }

            urlBuilder.setParameter("event_id","register_web");//区分是交易还是注册
            //ip mobile
            urlBuilder.setParameter("ip_address",ip);
            urlBuilder.setParameter("account_mobile",mobile);
            String response = Request.Get(urlBuilder.build()).connectTimeout(200).socketTimeout(500).execute().returnContent().asString();//连接200 执行300
            Map result = Utils.JSON.parseObject(response, Map.class);

            if(result != null && result.get("success").toString().toLowerCase().equals("true"))
            {
                score = result.get("final_score").toString();
                // Cache
                if (!score.isEmpty()) {
                    cache.set(cacheKey, score);
                    cache.expire(cacheKey, cacheExpireTime);
                }
            }
        }catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke TongDunService.queryR fault.", ex);
            TraceLogger.traceLog("执行TongDunService.queryR异常: " + ex.toString());
        } finally {
            afterInvoke("TongDunService.queryR");
        }
        return score;
    }
}
