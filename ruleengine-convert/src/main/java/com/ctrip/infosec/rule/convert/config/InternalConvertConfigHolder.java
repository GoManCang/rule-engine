package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.event.DataUnitMetadata;
import com.ctrip.infosec.configs.event.InternalRiskFactDefinitionConfig;
import com.ctrip.infosec.configs.event.InternalRiskFactPersistConfig;
import com.ctrip.infosec.configs.event.RiskFactConvertRuleConfig;
import com.ctrip.infosec.configs.utils.Utils;
import com.google.common.collect.Maps;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class InternalConvertConfigHolder {
    private static final long PURGE_TIMEOUT = DateUtils.MILLIS_PER_MINUTE;
    private static long lastPurgeTime = System.currentTimeMillis();
    /**
     * key 是 eventPoint
     */
    public static final Map<String,RiskFactConvertRuleConfig> localRiskConvertMappings=Maps.newHashMap();
    public static final Map<String,InternalRiskFactDefinitionConfig> localRiskFactDefinitionConfigMap =Maps.newHashMap();

    public static Logger logger= LoggerFactory.getLogger(InternalConvertConfigHolder.class);


    /**
     * 重新配置
     *
     */
    public static void reconfigure(Map<String, RiskFactConvertRuleConfig> riskFactConvertRuleConfigMap,
                                                  Map<String,InternalRiskFactDefinitionConfig> riskFactDefinitionConfigMap
                                                 ){
        logger.info("==========================================================");
        logger.info(Utils.JSON.toPrettyJSONString(riskFactConvertRuleConfigMap));
        logger.info(Utils.JSON.toPrettyJSONString(riskFactDefinitionConfigMap));
        logger.info("==========================================================");


        if (MapUtils.isNotEmpty(riskFactConvertRuleConfigMap)){
            for(Map.Entry<String ,RiskFactConvertRuleConfig> entry:riskFactConvertRuleConfigMap.entrySet()){
                String key = entry.getKey();
                RiskFactConvertRuleConfig remoteConfig=entry.getValue();
                RiskFactConvertRuleConfig localConfig= localRiskConvertMappings.get(key);
                if(localConfig == null || localConfig.getUpdatedAt().before(remoteConfig.getUpdatedAt())){
                    localRiskConvertMappings.put(key,remoteConfig);
                }
            }
        }

        if (MapUtils.isNotEmpty(riskFactDefinitionConfigMap)){
            for(Map.Entry<String ,InternalRiskFactDefinitionConfig> entry:riskFactDefinitionConfigMap.entrySet()){
                String key = entry.getKey();
                InternalRiskFactDefinitionConfig remoteConfig=entry.getValue();
                InternalRiskFactDefinitionConfig localConfig= localRiskFactDefinitionConfigMap.get(key);
                if(localConfig == null || localConfig.getUpdatedAt().before(remoteConfig.getUpdatedAt())){
                    localRiskFactDefinitionConfigMap.put(key,remoteConfig);
                }
            }
        }
        logger.info("==========================================================");
        logger.info(Utils.JSON.toPrettyJSONString(localRiskConvertMappings));
        logger.info(Utils.JSON.toPrettyJSONString(localRiskFactDefinitionConfigMap));
        logger.info("==========================================================");

        // 清空过期配置
        long curTime = System.currentTimeMillis();
        if (curTime > lastPurgeTime + PURGE_TIMEOUT) {
            for (Iterator<Map.Entry<String,RiskFactConvertRuleConfig >> iter = localRiskConvertMappings.entrySet().iterator(); iter.hasNext();){
                Map.Entry<String, RiskFactConvertRuleConfig> entry = iter.next();
                if (localRiskConvertMappings.get(entry.getKey()) == null && entry.getValue().getUpdatedAt().getTime() < curTime - PURGE_TIMEOUT){
                    iter.remove();
                }
            }
            for (Iterator<Map.Entry<String, InternalRiskFactDefinitionConfig>> iter = localRiskFactDefinitionConfigMap.entrySet().iterator(); iter.hasNext();){
                Map.Entry<String, InternalRiskFactDefinitionConfig> entry = iter.next();
                if (localRiskFactDefinitionConfigMap.get(entry.getKey()) == null && entry.getValue().getUpdatedAt().getTime() < curTime - PURGE_TIMEOUT){
                    iter.remove();
                }
            }
        }

        logger.info("==========================================================");
        logger.info(Utils.JSON.toPrettyJSONString(localRiskConvertMappings));
        logger.info(Utils.JSON.toPrettyJSONString(localRiskFactDefinitionConfigMap));
        logger.info("==========================================================");



    }
}
