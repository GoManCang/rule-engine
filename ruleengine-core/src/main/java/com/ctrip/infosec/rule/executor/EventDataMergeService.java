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
        beforeInvoke();
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
            fault();
            logger.error(Contexts.getLogPrefix() + "exec execute merge fault.", ex);
        } finally {
            afterInvoke("EventDataMergeService.executeRedisMerge");
        }
        return fact;
    }

    /**
     * 处理从redis获取数据
     */
    public RiskFact executeRedisGet(RiskFact fact) {
        beforeInvoke();
        try {
            Map<String, Map<String, String>> fieldsToGet = Configs.getEventMergeFieldsToGet(fact);
            //read and merge data to current fact
            if (fieldsToGet != null && !fieldsToGet.isEmpty()) {
                readAndMerge(fact, fieldsToGet);
            }
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "exec executeRedisGet fault.", ex);
        } finally {
            afterInvoke("EventDataMergeService.executeRedisGet");
        }
        return fact;
    }

    /**
     * 处理推送数据到redis
     */
    public RiskFact executeRedisPut(RiskFact fact) {
        beforeInvoke();
        try {
            //send data to redis for next get
            Map<String, Set<String>> fieldsToPut = Configs.getEventMergeFieldsToPut(fact);
            if (fieldsToPut != null && !fieldsToPut.isEmpty()) {
                sendToRedis(fact, fieldsToPut);
            }
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "exec executeRedisPut fault.", ex);
        } finally {
            afterInvoke("EventDataMergeService.executeRedisPut");
        }
        return fact;
    }

    /**
     * 从Redis获取数据并且合并到当前的fact中 获取的是多个eventPoint对应的合并的key
     */
    private RiskFact readAndMerge(RiskFact fact, Map<String, Map<String, String>> fields) {
        Iterator iterator = fields.keySet().iterator();
        while (iterator.hasNext()) {
            Object redisKey = iterator.next();
            TraceLogger.traceLog("&gt;&gt; CacheKey: " + redisKey);
            Map<String, String> newNodeNames = fields.get(redisKey);

            CacheProvider cache = CacheProviderFactory.getCacheProvider(clusterName);
            String redisValue = cache.get((String) redisKey);
            if (redisValue == null || redisValue.isEmpty()) {
                continue;
            }

            Map<String, Object> redisValues = JSON.parseObject(redisValue, Map.class);//check this line
            Iterator iteratorKeys = newNodeNames.keySet().iterator();
            //Iterator iteratorValues = redisValues.keySet().iterator();
            while (iteratorKeys.hasNext()) {
                String oldName = (String) iteratorKeys.next();
                String newName = newNodeNames.get(oldName);
                Object newValue = redisValues.get(oldName);
                if (newName == null || newName.toString().isEmpty() || newValue == null || newValue.toString().isEmpty()) {
                    continue;
                }
                if (newValue instanceof Map || newValue instanceof List || newValue instanceof Object[]) {
                    TraceLogger.traceLog("GET: " + oldName + " &DoubleRightArrow; " + newName + ", value = " + JSON.toJSONString(newValue));
                } else {
                    TraceLogger.traceLog("GET: " + oldName + " &DoubleRightArrow; " + newName + ", value = " + newValue);
                }
                fact.eventBody.put(newName, newValue);
            }
        }
        return fact;
    }

    /**
     * 把数据写到redis中供后面读取
     */
    private RiskFact sendToRedis(RiskFact fact, Map<String, Set<String>> fieldsToPut) {
        Iterator iterator = fieldsToPut.keySet().iterator();
        while (iterator.hasNext()) {
            Object redisKey = iterator.next();
            TraceLogger.traceLog("&gt;&gt; CacheKey: " + redisKey);
            if (redisKey == null || redisKey.toString().isEmpty()) {
                continue;
            }
            Iterator valuesIterator = fieldsToPut.get(redisKey).iterator();
            Map<String, Object> redisValueMap = new HashMap<String, Object>();
            while (valuesIterator.hasNext()) {
                Object newName = valuesIterator.next();
                Object newValue = fact.eventBody.get(newName);
                if (newName == null || newName.toString().isEmpty() || newValue == null || newValue.toString().isEmpty()) {
                    continue;
                }
                if (newValue instanceof Map || newValue instanceof List || newValue instanceof Object[]) {
                    TraceLogger.traceLog("PUT: " + newName + " = " + JSON.toJSONString(newValue));
                } else {
                    TraceLogger.traceLog("PUT: " + newName + " = " + newValue);
                }
                redisValueMap.put((String) newName, newValue);
            }

            String redisValueStr = JSON.toJSONString(redisValueMap);
            Integer liveTime = Configs.getEventMergeCacheKeyTTL(fact.getEventPoint());

            CacheProvider cache = CacheProviderFactory.getCacheProvider(clusterName);
            cache.set((String) redisKey, redisValueStr);
            cache.expire((String) redisKey, liveTime);
        }
        return fact;
    }
}
