/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.resource.CardInfo;
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
@Service("cardInfoDecryptConverter")
public class CardInfoDecryptConverter implements Converter {

    private static final Logger logger = LoggerFactory.getLogger(CardInfoDecryptConverter.class);

    @Override
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String cardInfoIdFieldName = (String) fieldMapping.get(fields[0].getParamName());
        String cardInfoIdFieldValue = BeanUtils.getNestedProperty(fact.eventBody, cardInfoIdFieldName);

        // prefix default value
        if (Strings.isNullOrEmpty(resultWrapper)) {
            resultWrapper = cardInfoIdFieldName + "_CardInfo";
        }
        // 执行过了就跳过
        if (fact.eventBody.containsKey(resultWrapper)) {
            return;
        }

        if (StringUtils.isNotBlank(cardInfoIdFieldValue)) {
            Map params = ImmutableMap.of("cardInfoId", cardInfoIdFieldValue);
            Map<String, Object> result = CardInfo.query("getinfo", params);
            if (result != null && !result.isEmpty()) {
                fact.eventBody.put(resultWrapper, result);
            } else {
                TraceLogger.traceLog("预处理结果为空. cardInfoId=" + cardInfoIdFieldValue);
            }
        }
    }

}
