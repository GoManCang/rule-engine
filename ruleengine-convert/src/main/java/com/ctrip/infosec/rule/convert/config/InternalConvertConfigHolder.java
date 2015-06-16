package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.event.RiskFactConvertRuleConfig;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.time.DateUtils;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class InternalConvertConfigHolder {
    //    private static Map<String, List<InternalMappingConfigTree>> riskConvertMappings = Maps.newHashMap();
    private static long purgeTimeout = DateUtils.MILLIS_PER_DAY;

    private static Map<String,RiskFactConvertRuleConfig> riskConvertMappings=Maps.newHashMap();

    /**
     * 重新配置
     *
     */
    public static synchronized void reconfigurate(Map<String, RiskFactConvertRuleConfig> convertRuleClientConfigMap){
        /**
         * 将已有的List 全部清空
         */
        for(Map.Entry<String,RiskFactConvertRuleConfig> entry:riskConvertMappings.entrySet()){
            entry.setValue(null);
        }
        /**
         * 更新client提供的RiskFactConvertRuleConfig
         */
        for (Map.Entry<String, RiskFactConvertRuleConfig> entry : convertRuleClientConfigMap.entrySet()) {
//            String eventPoint = entry.getKey();
            riskConvertMappings.put(entry.getKey(),entry.getValue());
//            tryUpdateConfig(eventPoint, entry.getValue());
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


}
