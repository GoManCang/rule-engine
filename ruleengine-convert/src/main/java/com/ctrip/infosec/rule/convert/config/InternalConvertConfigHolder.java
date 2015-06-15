package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.event.RiskFactConvertRuleConfig;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.time.DateUtils;

import java.util.List;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class InternalConvertConfigHolder {
    private static Map<String, List<InternalMappingConfigTree>> riskConvertMappings = Maps.newHashMap();
    private static long purgeTimeout = DateUtils.MILLIS_PER_DAY;

    /**
     * 重新配置
     * @param convertRuleConfigMap
     */
    public static synchronized void reconfigurate(Map<String, RiskFactConvertRuleConfig> convertRuleClientConfigMap){
        for (Map.Entry<String, RiskFactConvertRuleConfig> entry : convertRuleClientConfigMap.entrySet()) {
            String eventPoint = entry.getKey();
            tryUpdateConfig(eventPoint, entry.getValue());
        }
    }

    private static void tryUpdateConfig(String eventPoint, RiskFactConvertRuleConfig clientConfig) {
        List<InternalMappingConfigTree> internalMappingConfigs = riskConvertMappings.get(eventPoint);
    }
}
