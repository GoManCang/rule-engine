package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.event.InternalRiskFactDefinitionConfig;
import com.ctrip.infosec.configs.event.RiskFactConvertRuleConfig;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.time.DateUtils;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class InternalConvertConfigHolder {
    private static long purgeTimeout = DateUtils.MILLIS_PER_DAY;

    /**
     * key 是 eventPoint
     */
    private static Map<String,RiskFactConvertRuleConfig> riskConvertMappings=Maps.newHashMap();
    private static Map<String,InternalRiskFactDefinitionConfig> riskFactDefinitionConfigMap =Maps.newHashMap();


    /**
     * 重新配置
     *
     */
    public static synchronized void reconfigure(Map<String, RiskFactConvertRuleConfig> convertRuleClientConfigMap,
                                                Map<String, InternalRiskFactDefinitionConfig> convertDefinitionConfigMap){
        updateRiskConvertMappings(convertRuleClientConfigMap);
        updateRiskFactDefinitionConfigMap(convertDefinitionConfigMap);

    }

    private static void updateRiskFactDefinitionConfigMap(Map<String,InternalRiskFactDefinitionConfig> convertDefinitionConfigMap){
        /**
         * 将已有的全部清空
         */
        for(Map.Entry<String,InternalRiskFactDefinitionConfig> entry:riskFactDefinitionConfigMap.entrySet()){
            entry.setValue(null);
        }
        /**
         * 更新client提供的InternalRiskFactDefinitionConfig
         */
        for (Map.Entry<String, InternalRiskFactDefinitionConfig> entry : convertDefinitionConfigMap.entrySet()) {
            riskFactDefinitionConfigMap.put(entry.getKey(), entry.getValue());
        }
        /**
         * 将key对应的null去除
         */
        for(Map.Entry<String,RiskFactConvertRuleConfig> entry:riskConvertMappings.entrySet()){
            if(entry.getValue()==null){
                riskFactDefinitionConfigMap.remove(entry.getKey());
            }
        }
    }

    private static void updateRiskConvertMappings(Map<String, RiskFactConvertRuleConfig> convertRuleClientConfigMap){
        /**
         * 将已有的 全部清空
         */
        for(Map.Entry<String,RiskFactConvertRuleConfig> entry:riskConvertMappings.entrySet()){
            entry.setValue(null);
        }
        /**
         * 更新client提供的RiskFactConvertRuleConfig
         */
        for (Map.Entry<String, RiskFactConvertRuleConfig> entry : convertRuleClientConfigMap.entrySet()) {
            riskConvertMappings.put(entry.getKey(),entry.getValue());
        }
        /**
         * 将key对应的null去除
         */
        for(Map.Entry<String,RiskFactConvertRuleConfig> entry:riskConvertMappings.entrySet()){
            if(entry.getValue()==null){
                riskConvertMappings.remove(entry.getKey());
            }
        }
    }

//    private static void tryUpdateConfig(String eventPoint, RiskFactConvertRuleConfig clientConfig) {
//        RiskFactConvertRuleConfig riskFactConvertRuleConfig = riskConvertMappings.get(eventPoint);
//        /**
//         * map 中没有接入点对应的 RiskFactConvertRuleConfig list
//         */
//            riskConvertMappings.put(eventPoint, riskFactConvertRuleConfig);
//
//    }

    public static Map<String, RiskFactConvertRuleConfig> getRiskConvertMappings() {
        return riskConvertMappings;
    }

    public static Map<String, InternalRiskFactDefinitionConfig> getRiskFactDefinitionConfigMap() {
        return riskFactDefinitionConfigMap;
    }

}
