/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.rule.resource.DataProxy;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import java.util.List;
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
@Service("userProfileTagsConverter")
public class UserProfileTagsConverter implements Converter {

    private static final Logger logger = LoggerFactory.getLogger(UserProfileTagsConverter.class);

    static final String serviceName = "UserProfileService";
    static final String operationName = "DataQuery";

    @Override
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String uidFieldName = (String) fieldMapping.get(fields[0].getParamName());
        String uidFieldValue = BeanUtils.getNestedProperty(fact.eventBody, uidFieldName);
        String tagsFieldValue = (String) fieldMapping.get(fields[1].getParamName());

        if (StringUtils.isBlank(uidFieldValue) || StringUtils.isBlank(tagsFieldValue)) {
            return;
        }

        List<String> tags = Splitter.on(",").omitEmptyStrings().trimResults().splitToList(tagsFieldValue);

        // prefix default value
        if (Strings.isNullOrEmpty(resultWrapper)) {
            resultWrapper = uidFieldName + "_ProfileInfo";
        }
        // 执行过了就跳过
        if (fact.eventBody.containsKey(resultWrapper)) {
            return;
        }

        Map params = ImmutableMap.of("uid", uidFieldValue, "tagNames", tags);
        Map result = DataProxy.queryProfileTagsForMap(serviceName, operationName, params);
        if (result != null && !result.isEmpty()) {
            fact.eventBody.put(resultWrapper, result);
        }
    }

}
