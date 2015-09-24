/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import static com.ctrip.infosec.configs.utils.EventBodyUtils.valueAsString;
import com.ctrip.infosec.rule.resource.DataProxy;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 *
 * @author zhengby
 */
@Service("ip2ProvinceCityConverter")
public class Ip2ProvinceCityConverter implements Converter {

    private static final Logger logger = LoggerFactory.getLogger(Ip2ProvinceCityConverter.class);

    static final String serviceName = "IpService";
    static final String operationName = "getIpArea";

    @Override
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper, boolean isAsync) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String ipFieldName = (String) fieldMapping.get(fields[0].getParamName());
        String ipFieldValue = valueAsString(fact.eventBody, ipFieldName);

        // prefix default value
        if (Strings.isNullOrEmpty(resultWrapper)) {
            resultWrapper = ipFieldName + "_IpArea";
        }
        // 执行过了就跳过
        if (fact.eventBody.containsKey(resultWrapper)) {
            return;
        }

        // "8.8.8.8:80"
        ipFieldValue = StringUtils.trimToEmpty(ipFieldValue);
        ipFieldValue = StringUtils.removeStart(ipFieldValue, "\"");
        ipFieldValue = StringUtils.removeEnd(ipFieldValue, "\"");
        ipFieldValue = StringUtils.substringBefore(ipFieldValue, ":");

        if (StringUtils.isNotBlank(ipFieldValue) && !"127.0.0.1".equals(ipFieldValue)) {
            Map params = ImmutableMap.of("ip", ipFieldValue);
            Map result = DataProxy.queryForMap(serviceName, operationName, params);
            if (result != null && !result.isEmpty()) {
                fact.eventBody.put(resultWrapper, result);
            } else {
                TraceLogger.traceLog("预处理结果为空. ip=" + ipFieldValue);
            }
        }
    }

}
