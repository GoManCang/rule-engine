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
@Service("crmMemberInfoConverter")
public class CrmMemberInfoConverter implements Converter {

    private static final Logger logger = LoggerFactory.getLogger(CrmMemberInfoConverter.class);

    static final String serviceName = "CRMService";
    static final String operationName = "getMemberInfo";

    @Override
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String uidFieldName = (String) fieldMapping.get(fields[0].getParamName());
        String uidFieldValue = BeanUtils.getNestedProperty(fact.eventBody, uidFieldName);

        // prefix default value
        if (Strings.isNullOrEmpty(resultWrapper)) {
            resultWrapper = uidFieldName + "_MemberInfo";
        }
        // 执行过了就跳过
        if (fact.eventBody.containsKey(resultWrapper)) {
            return;
        }

        if (StringUtils.isNotBlank(uidFieldValue)) {
            Map params = ImmutableMap.of("uid", uidFieldValue);
            Map result = DataProxy.queryForMap(serviceName, operationName, params);
            if (result != null && !result.isEmpty()) {
                fact.eventBody.put(resultWrapper, result);
            }
        }
    }

}
