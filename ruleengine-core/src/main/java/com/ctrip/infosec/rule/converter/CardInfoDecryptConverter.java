/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.resource.CardInfo;
import com.ctrip.infosec.rule.resource.Crypto;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;

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
@Service("cardInfoDecryptConverter")
public class CardInfoDecryptConverter implements Converter {

    private static final Logger logger = LoggerFactory.getLogger(CardInfoDecryptConverter.class);

    @Override
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper, boolean isAsync) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String cardInfoIdFieldName = (String) fieldMapping.get(fields[0].getParamName());

        Object value = fact.eventBody.get((cardInfoIdFieldName.split("\\.")[0]));
        if (value.getClass().isArray() || value instanceof List) {
            convertPaymentInfos(preAction, cardInfoIdFieldName, fact, resultWrapper);
            return;
        }

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
//                try {
//                    String CreditCardNumber = (String) result.get("CreditCardNumber");
//                    if (StringUtils.isNotBlank(CreditCardNumber)) {
//                        String CreditCardNumberPlaintext = Crypto.decrypt(CreditCardNumber);
//                        if (StringUtils.isNotBlank(CreditCardNumberPlaintext)) {
//                            result.put("CreditCardNumberPlaintext", CreditCardNumberPlaintext);
//                        }
//                    }
//                } catch (Exception ex) {
//                    TraceLogger.traceLog("解密CreditCardNumber异常: " + ex.toString());
//                }
                fact.eventBody.put(resultWrapper, result);
            } else {
                TraceLogger.traceLog("预处理结果为空. cardInfoId=" + cardInfoIdFieldValue);
            }
        }
    }

    private void convertPaymentInfos(PreActionEnums preAction,
            String cardInfoIdFieldName, RiskFact fact, String resultWrapper) throws Exception {

        List<Object> dataSources = null;
        Object object = fact.eventBody.get((cardInfoIdFieldName.split("\\.")[0]));

        if (object.getClass().isArray()) {
            dataSources = Lists.newArrayList((Object[]) object);
        } else {
            dataSources = (List<Object>) object;
        }

        for (Object obj : dataSources) {

            Map map = (Map) obj;
            String cardInfoIdFieldValue = BeanUtils.getNestedProperty(map, cardInfoIdFieldName.substring(cardInfoIdFieldName.lastIndexOf(".") + 1));

            if (StringUtils.isNotBlank(cardInfoIdFieldValue)) {
                Map params = ImmutableMap.of("cardInfoId", cardInfoIdFieldValue);
                Map<String, Object> result = CardInfo.query("getinfo", params);
                if (result != null && !result.isEmpty()) {
//                    try {
//                        String CreditCardNumber = (String) result.get("CreditCardNumber");
//                        if (StringUtils.isNotBlank(CreditCardNumber)) {
//                            String CreditCardNumberPlaintext = Crypto.decrypt(CreditCardNumber);
//                            if (StringUtils.isNotBlank(CreditCardNumberPlaintext)) {
//                                result.put("CreditCardNumberPlaintext", CreditCardNumberPlaintext);
//                            }
//                        }
//                    } catch (Exception ex) {
//                        TraceLogger.traceLog("解密CreditCardNumber异常: " + ex.toString());
//                    }
                    map.put(resultWrapper, result);
                } else {
                    TraceLogger.traceLog("预处理结果为空. cardInfoId=" + cardInfoIdFieldValue);
                    map.put(resultWrapper, ImmutableMap.of("cardInfoId", cardInfoIdFieldValue));
                }
            }
        }
    }

}
