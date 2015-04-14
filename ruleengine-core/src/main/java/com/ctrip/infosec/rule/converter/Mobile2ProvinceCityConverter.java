/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
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
@Service("mobile2ProvinceCityConverter")
public class Mobile2ProvinceCityConverter implements Converter {

    private static final Logger logger = LoggerFactory.getLogger(Mobile2ProvinceCityConverter.class);

    static final String serviceName = "MobilePhoneService";
    static final String operationName = "getMobileArea";

    @Override
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String mobileFieldName = (String) fieldMapping.get(fields[0].getParamName());
        String mobileFieldValue = BeanUtils.getNestedProperty(fact.eventBody, mobileFieldName);

        // prefix default value
        if (Strings.isNullOrEmpty(resultWrapper)) {
            resultWrapper = mobileFieldName + "_MobileArea";
        }
        // 执行过了就跳过
        if (fact.eventBody.containsKey(resultWrapper)) {
            return;
        }

        if (StringUtils.isNotBlank(mobileFieldValue)) {
            Map params = ImmutableMap.of("mobileNumber", mobileFieldValue);
            Map result = DataProxy.queryForMap(serviceName, operationName, params);
            if (result != null && !result.isEmpty()) {
                fact.eventBody.put(resultWrapper, result);
            }
        }
    }

}
