package com.ctrip.infosec.rule.executor;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.redis.CacheProviderFactory;
import credis.java.client.CacheProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import org.apache.commons.lang3.StringUtils;

/**
 * Created by lpxie on 15-3-20.
 */
public class EventDataMergeService {

    private static Logger logger = LoggerFactory.getLogger(EventDataMergeService.class);
    public static final String clusterName = "CounterServer_03";

    /**
     * 处理推送数据到redis和从redis获取数据
     */
    public RiskFact executeRedisOption(RiskFact fact) {
        beforeInvoke("EventMerge.Get");
        try {
            Map<String, Map<String, String>> fieldsToGet = Configs.getEventMergeFieldsToGet(fact);
            //read and merge data to current fact
            if (fieldsToGet != null && !fieldsToGet.isEmpty()) {
                readAndMerge(fact, fieldsToGet);
            }
            //send data to redis for next get
            Map<String, Set<String>> fieldsToPut = Configs.getEventMergeFieldsToPut(fact);
            if (fieldsToPut != null && !fieldsToPut.isEmpty()) {
                sendToRedis(fact, fieldsToPut);
            }
        } catch (Exception ex) {
            fault("EventMerge.Get");
            logger.error(Contexts.getLogPrefix() + "exec execute merge fault.", ex);
        } finally {
            afterInvoke("EventMerge.Get");
        }
        return fact;
    }

    /**
     * 处理从redis获取数据
     */
    public RiskFact executeRedisGet(RiskFact fact) {
        try {
            Map<String, Map<String, String>> fieldsToGet = Configs.getEventMergeFieldsToGet(fact);
            //read and merge data to current fact
            if (fieldsToGet != null && !fieldsToGet.isEmpty()) {
                readAndMerge(fact, fieldsToGet);
            }
        } catch (Exception ex) {
            logger.error(Contexts.getLogPrefix() + "exec executeRedisGet fault.", ex);
        }
        return fact;
    }

    /**
     * 处理推送数据到redis
     */
    public RiskFact executeRedisPut(RiskFact fact) {
        beforeInvoke("EventMerge.Put");
        try {
            //send data to redis for next get
            Map<String, Set<String>> fieldsToPut = Configs.getEventMergeFieldsToPut(fact);
            if (fieldsToPut != null && !fieldsToPut.isEmpty()) {
                sendToRedis(fact, fieldsToPut);
            }
        } catch (Exception ex) {
            fault("EventMerge.Put");
            logger.error(Contexts.getLogPrefix() + "exec executeRedisPut fault.", ex);
        } finally {
            afterInvoke("EventMerge.Put");
        }
        return fact;
    }

    /**
     * 从Redis获取数据并且合并到当前的fact中 获取的是多个eventPoint对应的合并的key
     */
    RiskFact readAndMerge(RiskFact fact, Map<String, Map<String, String>> fieldsToGet) {
        for (String key : fieldsToGet.keySet()) {
            TraceLogger.traceLog("&gt;&gt; CacheKey: " + key);
            Map<String, String> fieldMapping = fieldsToGet.get(key);

            CacheProvider cache = CacheProviderFactory.getCacheProvider(clusterName);
            String value = cache.get(key);
            if (value == null || value.isEmpty()) {
                continue;
            }

            Map<String, Object> valueMap = JSON.parseObject(value, Map.class);
            if (valueMap == null) {
                continue;
            }

            for (String sourceFieldName : fieldMapping.keySet()) {
                String targetFieldName = fieldMapping.get(sourceFieldName);
                Object targetFieldValue = valueMap.get(sourceFieldName);
                if (StringUtils.isEmpty(targetFieldName)
                        || targetFieldValue == null
                        || (targetFieldValue instanceof String && StringUtils.isEmpty((String) targetFieldValue))) {
                    continue;
                }
                // eventBody对应的KEY有值的话 不覆盖
                Object fv = fact.eventBody.get(targetFieldName);
                if (valueIsEmpty(fv)) {

                    if (targetFieldValue instanceof Map || targetFieldValue instanceof List || targetFieldValue instanceof Object[]) {
                        TraceLogger.traceLog("GET: " + sourceFieldName + " &DoubleRightArrow; " + targetFieldName + ", value = " + JSON.toJSONString(targetFieldValue));
                    } else {
                        TraceLogger.traceLog("GET: " + sourceFieldName + " &DoubleRightArrow; " + targetFieldName + ", value = " + targetFieldValue);
                    }
                    fact.eventBody.put(targetFieldName, targetFieldValue);
                }
            }
        }
        return fact;
    }

    /**
     * 把数据写到redis中供后面读取
     */
    RiskFact sendToRedis(RiskFact fact, Map<String, Set<String>> fieldsToPut) {
        for (String key : fieldsToPut.keySet()) {
            TraceLogger.traceLog("&gt;&gt; CacheKey: " + key);
            if (key == null || key.isEmpty()) {
                continue;
            }

            CacheProvider cache = CacheProviderFactory.getCacheProvider(clusterName);
            Map<String, Object> valueMap = new HashMap<String, Object>();
            // key已存在的话 则合并非空项
            boolean exists = cache.exists(key);
            if (exists) {
                String value = cache.get(key);
                if (StringUtils.isNotBlank(value)) {
                    Map<String, Object> tempValueMap = JSON.parseObject(value, Map.class);
                    if (tempValueMap != null) {
                        valueMap = tempValueMap;
                    }
                }
            }
            Set<String> fields = fieldsToPut.get(key);
            for (String fieldName : fields) {
                Object fv = fact.eventBody.get(fieldName);
                if (valueIsEmpty(fv)) {
                    continue;
                }
                if (fv instanceof Map || fv instanceof List || fv instanceof Object[]) {
                    TraceLogger.traceLog("PUT: " + fieldName + " = " + JSON.toJSONString(fv));
                } else {
                    TraceLogger.traceLog("PUT: " + fieldName + " = " + fv);
                }
                valueMap.put(fieldName, fv);
            }

            String value = JSON.toJSONString(valueMap);
            Integer ttl = Configs.getEventMergeCacheKeyTTL(fact.getEventPoint());

            cache.set(key, value);
            cache.expire(key, ttl);
        }
        return fact;
    }

    boolean valueIsEmpty(Object fv) {
        if (fv == null
                || (fv instanceof String && StringUtils.isEmpty((String) fv))
                || (fv instanceof Number && ((Number) fv).doubleValue() == 0.0)
                || (fv instanceof Map && ((Map) fv).isEmpty())
                || (fv instanceof List && ((List) fv).isEmpty())
                || (fv instanceof Object[] && ((Object[]) fv).length == 0)) {
            return true;
        }
        return false;
    }
}
