/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.resource.DataProxy;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import java.util.Map;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 *
 * @author zhengby
 */
@Service("airport3Code2CityConverter")
public class Airport3Code2CityConverter implements Converter {

    private static final Logger logger = LoggerFactory.getLogger(Ip2ProvinceCityConverter.class);

    static final String serviceName = "AirPortService";
    static final String operationName = "getAirPortCity";

    @Override
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper, boolean isAsync) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String airport3codeFieldName = (String) fieldMapping.get(fields[0].getParamName());
        String airport3codeFieldValue = BeanUtils.getNestedProperty(fact.eventBody, airport3codeFieldName);

        // prefix default value
        if (Strings.isNullOrEmpty(resultWrapper)) {
            resultWrapper = airport3codeFieldName + "_AirPortCity";
        }
        // 执行过了就跳过
        if (fact.eventBody.containsKey(resultWrapper)) {
            return;
        }

        if (StringUtils.isNotBlank(airport3codeFieldValue)) {
            Map params = ImmutableMap.of("airport", airport3codeFieldValue);
            Map result = DataProxy.queryForMap(serviceName, operationName, params);
            if (result != null && !result.isEmpty()) {
                fact.eventBody.put(resultWrapper, result);
            } else {
                TraceLogger.traceLog("预处理结果为空. airport=" + airport3codeFieldValue);
            }
        }
    }

}
