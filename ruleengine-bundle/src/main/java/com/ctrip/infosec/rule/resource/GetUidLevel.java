package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.redis.CacheProviderFactory;
import com.ctrip.infosec.sars.util.GlobalConfig;
import credis.java.client.CacheProvider;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 15-8-6.
 */
public class GetUidLevel
{
    private static final Logger logger = LoggerFactory.getLogger(GetUidLevel.class);
    private static final String clusterName = "CounterServer_03";
    private static final String cacheKeyPrefix = "ResourceCache__UidLevel__";
    private static final int cacheExpireTime = 7*24 * 3600;

    private static final String urlPrefix = GlobalConfig.getString("GetUidLevel.REST.URL.Prefix");
    private static final int queryTimeout = GlobalConfig.getInteger("GetUidLevel.query.timeout", 1000);

    static String buildCacheKey(String uid) {
        StringBuilder builder = new StringBuilder(cacheKeyPrefix);
        builder.append(uid);
        return builder.toString();
    }

    public static String query(String uid,boolean isAsync)
    {
        beforeInvoke();
        String result = "";
        try
        {
            if (StringUtils.isBlank(uid))
            {
                return result;
            }

            // Cache
            CacheProvider cache = CacheProviderFactory.getCacheProvider(clusterName);
            String cacheKey = buildCacheKey(uid);
            String oldResult = cache.get(cacheKey);
            if (oldResult != null) {
                return oldResult;
            }

            if(!isAsync)
                return result;

            //从公共部门获取数据
            Map request = new HashMap();
            request.put("UID",uid);
            int threeMonthCount = 0;
            String threeMonthCountResponseTxt = "";
            try
            {
                threeMonthCountResponseTxt = Request.Post(urlPrefix + "/CMB-REPORT-REPORT/json/GetThreeMonthOrderCount")
                        .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                        .connectTimeout(queryTimeout)
                        .socketTimeout(queryTimeout)
                        .execute().returnContent().asString();
            } catch (IOException e)
            {
                e.printStackTrace();
            }
            Map threeMonthCountResponse = Utils.JSON.parseObject(threeMonthCountResponseTxt, Map.class);
            String threeMonthResultCode = threeMonthCountResponse.get("ResultCode").toString();
            if(!threeMonthResultCode.equals("Fail"))
            {
                threeMonthCount = Integer.parseInt(threeMonthCountResponse.get("OrderCount").toString());
            }else
            {
                return result;
            }

            int allCount = 0;
            String allCountResponseTxt = "";
            try
            {
                allCountResponseTxt = Request.Post(urlPrefix + "/CMB-REPORT-REPORT/json/GetDealCountByUid")
                        .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                        .connectTimeout(queryTimeout)
                        .socketTimeout(queryTimeout)
                        .execute().returnContent().asString();
            } catch (IOException e)
            {
                e.printStackTrace();
            }

            Map allCountResponse = Utils.JSON.parseObject(allCountResponseTxt, Map.class);
            String allCountResultCode = allCountResponse.get("ResultCode").toString();
            if(!allCountResultCode.equals("Fail"))
            {
                allCount = Integer.parseInt(allCountResponse.get("DealCount").toString());
            }else
            {
                return result;
            }

            int resultCount = allCount - threeMonthCount;
            if(resultCount>=3)
            {
                result = "REPEAT";
            }else
            {
                result = "NEW";
            }

            // Cache
            if (!result.isEmpty()) {
                cache.set(cacheKey, result);
                cache.expire(cacheKey, cacheExpireTime);
            }
        }catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke GetUidLevel.query fault.", ex);
            TraceLogger.traceLog("执行GetUidLevel异常: " + ex.toString());
        } finally {
            afterInvoke("GetUidLevel.query");
        }
        return result;
    }
}
