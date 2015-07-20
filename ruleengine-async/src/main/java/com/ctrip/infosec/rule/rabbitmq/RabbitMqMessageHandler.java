/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.common.model.RiskResult;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.*;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.configs.rule.monitor.RuleMonitorRepository;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.convert.RiskFactPersistStrategy;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.ctrip.infosec.rule.convert.offline4j.RiskEventConvertor;
import com.ctrip.infosec.rule.convert.persist.DbExecuteException;
import com.ctrip.infosec.rule.convert.persist.PersistColumnProperties;
import com.ctrip.infosec.rule.convert.persist.PersistContext;
import com.ctrip.infosec.rule.convert.persist.RdbmsInsert;
import com.ctrip.infosec.rule.executor.*;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.google.common.collect.Maps;
import com.meidusa.fastjson.JSON;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;

import static com.ctrip.infosec.common.SarsMonitorWrapper.*;

/**
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
    private RiskEventConvertor riskEventConvertor;
    @Autowired
    private Offline4jService offline4jService;

    public void handleMessage(Object message) throws Exception {
        RiskFact fact = null;
        String factTxt;
        InternalRiskFact internalRiskFact = null;
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

            boolean traceLoggerEnabled = MapUtils.getBoolean(fact.ext, Constants.key_traceLogger, true);
            TraceLogger.enabled(traceLoggerEnabled);

            // 执行Redis读取
            eventDataMergeService.executeRedisGet(fact);
            // 执行预处理            
            try {
                // 引入节点编号优化排序
                // S0 - 接入层同步前
                // S1 - 同步引擎
                // S2 - 接入层同步后
                // S3 - 异步引擎
                TraceLogger.beginTrans(fact.eventId, "S3");
                TraceLogger.setLogPrefix("[异步预处理]");
                preRulesExecutorService.executePreRules(fact, true);
            } finally {
                TraceLogger.commitTrans();
            }
            //执行推送数据到Redis
            eventDataMergeService.executeRedisPut(fact);
            // 执行异步规则
            try {
                TraceLogger.beginTrans(fact.eventId, "S3");
                TraceLogger.setLogPrefix("[异步规则]");
                rulesExecutorService.executeAsyncRules(fact);
            } finally {
                TraceLogger.commitTrans();
            }
            // 执行后处理
            try {
                TraceLogger.beginTrans(fact.eventId, "S3");
                TraceLogger.setLogPrefix("[异步后处理]");
                postRulesExecutorService.executePostRules(fact, true);
            } finally {
                TraceLogger.commitTrans();
            }
            //Counter推送规则处理
            try {
                TraceLogger.beginTrans(fact.eventId, "S3");
                TraceLogger.setLogPrefix("[Counter推送]");
                counterPushRuleExrcutorService.executeCounterPushRules(fact, true);
            } finally {
                TraceLogger.commitTrans();
            }
            // -------------------------------- 规则引擎结束 -------------------------------------- //

            internalRiskFact = offline4jService.saveForOffline(fact);

            // 落地规则结果
            beforeInvoke("CardRiskDB.CheckResultLog.saveRuleResult");
            try {
                TraceLogger.beginTrans(fact.eventId, "S3");
                TraceLogger.setLogPrefix("[保存CheckResultLog]");
                Long riskReqId = MapUtils.getLong(fact.ext, Constants.key_reqId);
                boolean outerReqId = true;
                if (internalRiskFact != null && riskReqId == null) {
                    riskReqId = internalRiskFact.getReqId();
                    outerReqId = false;
                }
                if (riskReqId != null && riskReqId > 0) {
                    if (!Constants.eventPointsWithScene.contains(fact.eventPoint)) {
                        TraceLogger.traceLog("reqId = " + riskReqId);
                        saveRuleResult(riskReqId, fact.eventPoint, fact.results, outerReqId);
                    } else {
                        TraceLogger.traceLog("reqId = " + riskReqId + " [适配]");
                        saveRuleResult(riskReqId, fact.eventPoint, fact.resultsGroupByScene, outerReqId);
                    }
                }
            } catch (Exception ex) {
                fault("CardRiskDB.CheckResultLog.saveRuleResult");
                logger.error(Contexts.getLogPrefix() + "保存规则执行结果至[InfoSecurity_CheckResultLog]表时发生异常.", ex);
            } finally {
                long usage = afterInvoke("CardRiskDB.CheckResultLog.saveRuleResult");
                TraceLogger.traceLog("耗时: " + usage + "ms");
                TraceLogger.commitTrans();
            }

        } catch (Throwable ex) {
            logger.error(Contexts.getLogPrefix() + "invoke handleMessage exception.", ex);
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
                    if (internalRiskFact != null) {
                        try {
                            Object eventObj = riskEventConvertor.convert(internalRiskFact, riskLevel, HeaderMappingBizType.Offline4J);
                            beforeInvoke("offlineMessageSender.sendToOffline");
                            offlineMessageSender.sendToOffline(eventObj);
                        } catch (Exception ex) {
                            fault("offlineMessageSender.sendToOffline");
                            logger.error(Contexts.getLogPrefix() + "send Offline4J message fault.", ex);
                        } finally {
                            afterInvoke("offlineMessageSender.sendToOffline");
                        }
                    }
                }

                try {

                    //遍历fact的所有results，如果有风险值大于0的，则进行计数操作
                    boolean withScene = Constants.eventPointsWithScene.contains(fact.eventPoint);
                    if (!withScene) {
                        for (Entry<String, Map<String, Object>> entry : fact.results.entrySet()) {

                            String ruleNo = entry.getKey();
                            int rLevel = NumberUtils.toInt(MapUtils.getString(entry.getValue(), Constants.riskLevel));

                            if (rLevel > 0) {
                                RuleMonitorRepository.increaseCounter(fact.getEventPoint(), ruleNo);
                            }

                        }
                    } else {
                        for (Entry<String, Map<String, Object>> entry : fact.resultsGroupByScene.entrySet()) {

                            String ruleNo = entry.getKey();
                            int rLevel = NumberUtils.toInt(MapUtils.getString(entry.getValue(), Constants.riskLevel));

                            if (rLevel > 0) {
                                RuleMonitorRepository.increaseCounter(fact.getEventPoint(), ruleNo);
                            }

                        }
                    }

                } catch (Exception ex) {
                    logger.error(Contexts.getLogPrefix() + "RuleMonitorRepository increaseCounter fault.", ex);
                }

            }
        }
    }

    private void saveRuleResult(Long riskReqId, String eventPoint, Map<String, Map<String, Object>> results, boolean outerReqId) throws DbExecuteException {
        RdbmsInsert insert = new RdbmsInsert();
        DistributionChannel channel = new DistributionChannel();
        channel.setChannelNo(RiskFactPersistStrategy.allInOne4ReqId);
        channel.setDatabaseType(DatabaseType.AllInOne_SqlServer);
        channel.setChannelDesc(RiskFactPersistStrategy.allInOne4ReqId);
        channel.setDatabaseURL(RiskFactPersistStrategy.allInOne4ReqId);
        insert.setChannel(channel);

        /**
         * [LogID] = 主键 [ReqID] [RuleType] [RuleID] = 0 [RuleName] [RiskLevel]
         * [RuleRemark] [CreateDate] = now [DataChange_LastTime] = now
         * [IsHighlight] = 1
         */
        if (MapUtils.isNotEmpty(results)) {
            for (Entry<String, Map<String, Object>> entry : results.entrySet()) {
                try {
                    Long riskLevel = MapUtils.getLong(entry.getValue(), Constants.riskLevel);
                    boolean isAsync = MapUtils.getBoolean(entry.getValue(), Constants.async, true);
                    if (riskLevel > 0) {
                        boolean withScene = Constants.eventPointsWithScene.contains(eventPoint);
                        if (withScene || isAsync || !outerReqId) {
                            if (withScene || isAsync) {
                                insert.setTable("InfoSecurity_CheckResultLog");
                            } else {
                                insert.setTable("RiskControl_CheckResultLog");
                            }
                            Map<String, PersistColumnProperties> map = Maps.newHashMap();
                            PersistColumnProperties props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.DB_PK);
                            props.setColumnType(DataUnitColumnType.Long);
                            map.put("LogID", props);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
                            props.setColumnType(DataUnitColumnType.Long);
                            props.setValue(riskReqId);
                            map.put("ReqID", props);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
                            props.setColumnType(DataUnitColumnType.String);
                            String ruleType = withScene ? (isAsync ? "SA" : "S") : (isAsync ? "NA" : "N");
                            props.setValue(ruleType);
                            map.put("RuleType", props);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
                            props.setColumnType(DataUnitColumnType.Int);
                            props.setValue(0);
                            map.put("RuleID", props);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
                            props.setColumnType(DataUnitColumnType.String);
                            props.setValue(entry.getKey());
                            map.put("RuleName", props);
                            TraceLogger.traceLog("[" + entry.getKey() + "] riskLevel = " + riskLevel + ", ruleType = " + ruleType);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
                            props.setColumnType(DataUnitColumnType.Long);
                            props.setValue(riskLevel);
                            map.put("RiskLevel", props);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
                            props.setColumnType(DataUnitColumnType.String);
                            props.setValue(MapUtils.getString(entry.getValue(), Constants.riskMessage));
                            map.put("RuleRemark", props);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.CUSTOMIZE);
                            props.setColumnType(DataUnitColumnType.Data);
                            props.setExpression("const:now:date");
                            map.put("CreateDate", props);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.CUSTOMIZE);
                            props.setColumnType(DataUnitColumnType.Data);
                            props.setExpression("const:now:date");
                            map.put("DataChange_LastTime", props);

                            props = new PersistColumnProperties();
                            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
                            props.setColumnType(DataUnitColumnType.Int);
                            props.setValue(0);
                            map.put("IsHighlight", props);

                            insert.setColumnPropertiesMap(map);

                            PersistContext ctx = new PersistContext();
                            insert.execute(ctx);
                        }
                    }
                } catch (Exception e) {
                    logger.error(Contexts.getLogPrefix() + "save InfoSecurity_CheckResultLog failed. reqId=" + riskReqId + ", result=" + entry, e);
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
