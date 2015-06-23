/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import static com.ctrip.infosec.configs.utils.Utils.JSON;

import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;

import com.ctrip.infosec.rule.convert.RiskFactConvertRuleService;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.common.model.RiskResult;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.CallbackRule;
import com.ctrip.infosec.configs.rule.monitor.RuleMonitorRepository;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.executor.CounterPushRulesExecutorService;
import com.ctrip.infosec.rule.executor.EventDataMergeService;
import com.ctrip.infosec.rule.executor.PostRulesExecutorService;
import com.ctrip.infosec.rule.executor.PreRulesExecutorService;
import com.ctrip.infosec.rule.executor.RulesExecutorService;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;

/**
 *
 * @author zhengby
 */
public class RabbitMqMessageHandler {

    private static Logger logger = LoggerFactory.getLogger(RabbitMqMessageHandler.class);

    @Autowired
    private RulesExecutorService rulesExecutorService;
    @Autowired
    private PreRulesExecutorService preRulesExecutorService;
    @Autowired
    private PostRulesExecutorService postRulesExecutorService;
    @Autowired
    private DispatcherMessageSender dispatcherMessageSender;
    @Autowired
    private CallbackMessageSender callbackMessageSender;
    @Autowired
    private EventDataMergeService eventDataMergeService;
    @Autowired
    private OfflineMessageSender offlineMessageSender;
    @Autowired
    private CounterPushRulesExecutorService counterPushRuleExrcutorService;

    @Autowired
    private RiskFactConvertRuleService riskFactConvertRuleService;

    public void handleMessage(Object message) throws Exception {
        RiskFact fact = null;
        String factTxt = null;
        long reqId;
        InternalRiskFact internalRiskFact;

        try {

            if (message instanceof byte[]) {
                factTxt = new String((byte[]) message, Constants.defaultCharset);
            } else if (message instanceof String) {
                factTxt = (String) message;
            } else {
                throw new IllegalArgumentException("消息格式只支持\"String\"或\"byte[]\"");
            }

            logger.info("MQ: fact=" + factTxt);
            fact = JSON.parseObject((String) factTxt, RiskFact.class);
            Contexts.setLogPrefix("[" + fact.eventPoint + "][" + fact.eventId + "] ");
            SarsMonitorContext.setLogPrefix(Contexts.getLogPrefix());

            //执行订单合并
            eventDataMergeService.executeRedisOption(fact);
            // 执行预处理
            preRulesExecutorService.executePreRules(fact, true);
            // 执行异步规则
            rulesExecutorService.executeAsyncRules(fact);
            // 执行后处理
            postRulesExecutorService.executePostRules(fact, true);
            //Counter推送规则处理
            counterPushRuleExrcutorService.executeCounterPushRules(fact, true);
            //riskfact 数据映射转换
            internalRiskFact = riskFactConvertRuleService.apply(fact);

        } catch (Throwable ex) {
            logger.error(Contexts.getLogPrefix() + "invoke query exception.", ex);
        } finally {
            if (fact != null) {
                // 发送给DataDispatcher
                try {
                    beforeInvoke();
                    dispatcherMessageSender.sendToDataDispatcher(fact);
                } catch (Exception ex) {
                    fault();
                    logger.error(Contexts.getLogPrefix() + "send dispatcher message fault.", ex);
                } finally {
                    afterInvoke("DispatcherMessageSender.sendToDataDispatcher");
                }

                int riskLevel = MapUtils.getInteger(fact.finalResult, Constants.riskLevel, 0);
                if (riskLevel > 0) {

                    // 发送Callback给PD
                    try {
                        beforeInvoke();
                        CallbackRule callbackRule = Configs.getCallbackRule(fact.eventPoint);
                        if (callbackRule != null && callbackRule.isEnabled()) {
                            callbackMessageSender.sendToPD(buildRiskResult(fact, callbackRule));
                        }
                    } catch (Exception ex) {
                        fault();
                        logger.error(Contexts.getLogPrefix() + "send callback message fault.", ex);
                    } finally {
                        afterInvoke("CallbackMessageSender.sendToPD");
                    }

                    // 发送Offline4J
//                    try {
//                        beforeInvoke();
//                        offlineMessageSender.sendToOffline(fact);
//                    } catch (Exception ex) {
//                        fault();
//                        logger.error(Contexts.getLogPrefix() + "send Offline4J message fault.", ex);
//                    } finally {
//                        afterInvoke("offlineMessageSender.sendToOffline");
//                    }
                }

                try {

                    //遍历fact的所有results，如果有风险值大于0的，则进行计数操作
                    for (Entry<String, Map<String, Object>> entry : fact.getResults().entrySet()) {

                        String ruleNo = entry.getKey();
                        int rLevel = NumberUtils.toInt(MapUtils.getString(entry.getValue(), Constants.riskLevel));

                        if (rLevel > 0) {
                            RuleMonitorRepository.increaseCounter(ruleNo);
                        }

                    }
                } catch (Exception ex) {
                    logger.error(Contexts.getLogPrefix() + "RuleMonitorRepository increaseCounter fault.", ex);
                }

            }
        }
    }

    /**
     * 组装Callback的报文
     */
    RiskResult buildRiskResult(RiskFact fact, CallbackRule callbackRule) {
        RiskResult result = new RiskResult();
        result.setEventPoint(fact.eventPoint);
        result.setEventId(fact.eventId);
        result.getResults().putAll(fact.finalResult);

        // 需要返回给PD的额外字段
        Map<String, String> fieldMapping = callbackRule.getFieldMapping();
        if (fieldMapping != null && !fieldMapping.isEmpty()) {
            for (String fieldName : fieldMapping.keySet()) {
                String newFieldName = fieldMapping.get(fieldName);
                Object fieldValue = getNestedProperty(fact, fieldName);
                if (fieldValue != null) {
                    result.getResults().put(newFieldName, fieldValue);
                }
            }
        }
//        result.getResults().put("orderId", fact.eventBody.get("orderID"));
//        result.getResults().put("hotelId", fact.eventBody.get("hotelID"));

        result.setRequestTime(fact.requestTime);
        result.setRequestReceive(fact.requestReceive);
        result.setResponseTime(Utils.fastDateFormatInMicroSecond.format(new Date()));
        return result;
    }

    Object getNestedProperty(Object factOrEventBody, String columnExpression) {
        try {
            Object value = PropertyUtils.getNestedProperty(factOrEventBody, columnExpression);
            return value;
        } catch (Exception ex) {
            logger.info(Contexts.getLogPrefix() + "getNestedProperty fault. message: " + ex.getMessage());
        }
        return null;
    }
}
