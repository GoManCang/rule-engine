package com.ctrip.infosec.rule.executor;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import credis.java.client.CacheProvider;
import credis.java.client.setting.RAppSetting;
import credis.java.client.util.CacheFactory;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

/**
 * Created by lpxie on 15-3-20.
 */
public class EventDataMergeService {

    private static Logger logger = LoggerFactory.getLogger(EventDataMergeService.class);
    private static CacheProvider cacheProvider;

    /**
     * redis相关的属性检查
     */
    static final String serviceUrl = GlobalConfig.getString("CRedis.serviceUrl");
    static final String appId = GlobalConfig.getString("appId");
    static final String provider = GlobalConfig.getString("CRedis.provider");

    static void check() {
        Validate.notEmpty(serviceUrl, "在GlobalConfig.properties里没有找到\"CRedis.serviceUrl\"配置项.");
        Validate.notEmpty(appId, "在GlobalConfig.properties里没有找到\"appId\"配置项.");
        Validate.notEmpty(provider, "在GlobalConfig.properties里没有找到\"CRedis.provider\"配置项.");
    }

    public void init() {
        check();
        logger.info(Contexts.getLogPrefix() + "Start to connect redis");
        RAppSetting.setAppID(appId);
        RAppSetting.setCRedisServiceUrl(serviceUrl);
        RAppSetting.setLogging(false);
        try {
            cacheProvider = CacheFactory.GetProvider(provider);
        } catch (RuntimeException exp) {
            logger.error(Contexts.getLogPrefix() + "Connect to redis failed by " + exp.getMessage());
        }
    }

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
    public RiskFact executeRedisGet(RiskFact fact)
    {
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
    public RiskFact executeRedisPut(RiskFact fact)
    {
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
            Map<String, String> newNodeNames = fields.get(redisKey);

            String redisValue = cacheProvider.get((String) redisKey);
            if (redisValue == null || redisValue.isEmpty()) {
                continue;
            }
            Map<String, Object> redisValues = JSON.parseObject(redisValue, Map.class);//check this line
            Iterator iteratorValues = redisValues.keySet().iterator();
            while (iteratorValues.hasNext()) {
                String oldName = (String) iteratorValues.next();
                String newName = newNodeNames.get(oldName);
                Object newValue = redisValues.get(oldName);
                if (newValue == null || newValue.toString().isEmpty()) {
                    continue;
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
            if (redisKey == null || redisKey.toString().isEmpty()) {
                continue;
            }
            Iterator valuesIterator = fieldsToPut.get(redisKey).iterator();
            Map<String, Object> redisValueMap = new HashMap<String, Object>();
            while (valuesIterator.hasNext()) {
                Object newName = valuesIterator.next();
                if (newName == null || newName.toString().isEmpty() || fact.eventBody.get(newName) == null || fact.eventBody.get(newName).toString().isEmpty()) {
                    continue;
                }
                redisValueMap.put((String) newName, fact.eventBody.get(newName));
            }

            String redisValueStr = JSON.toJSONString(redisValueMap);
            Integer liveTime = Configs.getEventMergeCacheKeyTTL(fact.getEventPoint());
            boolean sendSuccess = cacheProvider.set((String) redisKey, redisValueStr);
            boolean setExpireTime = cacheProvider.expire((String) redisKey, liveTime);
            if (!sendSuccess) {
                logger.error(Contexts.getLogPrefix() + "Send " + redisKey + "=" + redisValueStr + " into redis failed!");
            }
        }
        return fact;
    }
}
