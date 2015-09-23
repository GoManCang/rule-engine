/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.EventBodyUtils.valueAsString;
import com.ctrip.infosec.rule.resource.DataProxy;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;

import java.util.List;
import java.util.Map;
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
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper, boolean isAsync) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String uidFieldName = (String) fieldMapping.get(fields[0].getParamName());
        String uidFieldValue = valueAsString(fact.eventBody, uidFieldName);
        String tagsFieldValue = (String) fieldMapping.get(fields[1].getParamName());

        if (StringUtils.isBlank(uidFieldValue) || StringUtils.isBlank(tagsFieldValue)) {
            return;
        }

        List<String> _tags = Splitter.on(",").omitEmptyStrings().trimResults().splitToList(tagsFieldValue);
        List<String> tags = Lists.newArrayList(_tags);

        // prefix default value
        if (Strings.isNullOrEmpty(resultWrapper)) {
            resultWrapper = uidFieldName + "_ProfileInfo";
        }
        // 执行过了就跳过
        if (fact.eventBody.containsKey(resultWrapper)) {
            return;
        }

        //如果有cuscharacter则用新的接口
        if (tags.contains("CUSCHARACTER")) {
            tags.add("CUSCHARACTER_V2");
            tags.remove("CUSCHARACTER");
        }

        Map params = ImmutableMap.of("uid", uidFieldValue, "tagNames", tags);
        Map result = DataProxy.queryForMap(serviceName, operationName, params);
        if (result != null && !result.isEmpty()) {
            if (result.containsKey("CUSCHARACTER_V2")) {
                Object v = result.get("CUSCHARACTER_V2");
                result.put("CUSCHARACTER", v);
                result.remove("CUSCHARACTER_V2");
            }
            fact.eventBody.put(resultWrapper, result);
        }

    }

}
