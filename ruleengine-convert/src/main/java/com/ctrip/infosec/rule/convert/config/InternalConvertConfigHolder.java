package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.event.DataUnitMetadata;
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
     * key shi  dataUtils
     */
private static Map<String,DataUnitMetadata> riskFactMetadataMap = Maps.newHashMap();

    /**
     * 重新配置
     *
     */
    public static synchronized void reconfigure(Map<String, RiskFactConvertRuleConfig> convertRuleClientConfigMap,
                                                  Map<String,InternalRiskFactDefinitionConfig> convertDefinitionConfigMap,
                                                  Map<String,DataUnitMetadata> convertDataUnitMetadate){
        updateRiskConvertMappings(convertRuleClientConfigMap);
        updateRiskFactDefinitionConfigMap(convertDefinitionConfigMap);
        updateConvertDataUnitMetadate(convertDataUnitMetadate);

    }

    private static void updateRiskFactDefinitionConfigMap(Map<String,InternalRiskFactDefinitionConfig> convertDefinitionConfigMap){
        /**
         * 将已有的全部清空
         */

        //fixme  额 好像不能这么清空。map真在使用会 nullpointexception
        riskFactDefinitionConfigMap.clear();
        /**
         * 更新client提供的InternalRiskFactDefinitionConfig
         */
        for (Map.Entry<String, InternalRiskFactDefinitionConfig> entry : convertDefinitionConfigMap.entrySet()) {
            riskFactDefinitionConfigMap.put(entry.getKey(), entry.getValue());
        }
    }

    private static void updateRiskConvertMappings(Map<String, RiskFactConvertRuleConfig> convertRuleClientConfigMap){
        /**
         * 将已有的 全部清空
         */
        riskConvertMappings.clear();
        /**
         * 更新client提供的RiskFactConvertRuleConfig
         */
        for (Map.Entry<String, RiskFactConvertRuleConfig> entry : convertRuleClientConfigMap.entrySet()) {
            riskConvertMappings.put(entry.getKey(),entry.getValue());
        }
    }

    private static void updateConvertDataUnitMetadate(Map<String,DataUnitMetadata> convertDataUnitMetadate){
        /**
         * 将已有的 全部清空
         */
        riskFactMetadataMap.clear();
        /**
         * 更新client提供的RiskFactConvertRuleConfig
         */
        for (Map.Entry<String, DataUnitMetadata> entry : convertDataUnitMetadate.entrySet()) {
            riskFactMetadataMap.put(entry.getKey(), entry.getValue());
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

    public static Map<String, DataUnitMetadata> getRiskFactMetadataMap() {
        return riskFactMetadataMap;
    }
}
