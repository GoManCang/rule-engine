/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.ctrip.infosec.configs.event.*;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.rule.convert.RiskFactConvertRuleService;
import com.ctrip.infosec.rule.convert.RiskFactPersistStrategy;
import com.ctrip.infosec.rule.convert.persist.*;
import com.ctrip.infosec.rule.executor.*;
import com.ctrip.infosec.rule.resource.RiskLevelData;
import com.ctrip.infosec.rule.resource.model.SaveRiskLevelDataRequest;
import com.ctrip.infosec.rule.resource.model.SaveRiskLevelDataResponse;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.common.model.RiskResult;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.rule.monitor.RuleMonitorRepository;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.ctrip.infosec.rule.convert.offline4j.RiskEventConvertor;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.meidusa.fastjson.JSON;

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
    private PersistPreRuleExecutorService persistPreRuleExecutorService;
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
    private RiskFactConvertRuleService riskFactConvertRuleService;
    
    public void handleMessage(Object message) throws Exception {
        RiskFact fact = null;
        String factTxt = null;
        long reqId;
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

            // 执行Redis读取
            eventDataMergeService.executeRedisGet(fact);
            // 执行预处理            
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[异步预处理]");
                preRulesExecutorService.executePreRules(fact, true);
            } finally {
                TraceLogger.commitTrans();
            }
            //执行推送数据到Redis
            eventDataMergeService.executeRedisPut(fact);
            // 执行异步规则
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[异步规则]");
                rulesExecutorService.executeAsyncRules(fact);
            } finally {
                TraceLogger.commitTrans();
            }
            // 执行后处理
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[异步后处理]");
                postRulesExecutorService.executePostRules(fact, true);
            } finally {
                TraceLogger.commitTrans();
            }
            //Counter推送规则处理
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[Counter推送]");
                counterPushRuleExrcutorService.executeCounterPushRules(fact, true);
            } finally {
                TraceLogger.commitTrans();
            }
            // -------------------------------- 规则引擎结束 -------------------------------------- //

            // 执行落地前规则
            persistPreRuleExecutorService.executePostRules(fact, false);
            //riskfact 数据映射转换
            internalRiskFact = riskFactConvertRuleService.apply(fact);
            if (internalRiskFact != null) {
                // 数据落地
                String operation = internalRiskFact.getEventPoint() + ".persist-info";
                try {
                    beforeInvoke(operation);
                    Integer riskLevel = MapUtils.getInteger(fact.finalResult, Constants.riskLevel, 0);
                    String resultRemark = "NEW: " + resultToString(fact.results);
                    RiskFactPersistManager persistManager = RiskFactPersistStrategy.preparePersistence(internalRiskFact);
                    PersistContext persistContext = persistManager.persist(riskLevel, resultRemark);
                    reqId = persistManager.getGeneratedReqId();
                    internalRiskFact.setReqId(reqId);
                    // 调用远程服务落地
                    if (MapUtils.getBoolean(fact.ext, "offline4j-push-ebank", false)) {
                        SaveRiskLevelDataRequest request = new SaveRiskLevelDataRequest();
                        request.setResID(reqId);
                        request.setReqID(reqId);
                        request.setOrderID(persistManager.getLong("InfoSecurity_RiskLevelData.OrderID"));
                        request.setRiskLevel(riskLevel);
                        request.setRemark(persistManager.getString("InfoSecurity_RiskLevelData.Remark"));
                        request.setOrderType(persistManager.getInteger("InfoSecurity_RiskLevelData.OrderID"));
                        request.setOriginalRiskLevel(riskLevel);
                        Map<String, Object> ebankData = MapUtils.getMap(fact.ext, "ebank-data");
                        request.setInfoID(MapUtils.getInteger(ebankData, "infoId", 0));
                        request.setIsForigenCard(MapUtils.getString(ebankData, "isForeignCard", ""));
                        request.setCardInfoID(MapUtils.getInteger(ebankData, "cardInfoID", 0));
                        
                        SaveRiskLevelDataResponse ebankResp = RiskLevelData.save(request);
                        if (ebankResp != null) {
                            // 更新InfoSecurity_RiskLevelData的TransFlag = 32
                            RdbmsUpdate update = new RdbmsUpdate();
                            DistributionChannel channel = new DistributionChannel();
                            String allInOneDb = RiskFactPersistStrategy.allInOne4ReqId;
                            channel.setChannelNo(allInOneDb);
                            channel.setDatabaseType(DatabaseType.AllInOne_SqlServer);
                            channel.setChannelDesc(allInOneDb);
                            channel.setDatabaseURL(allInOneDb);
                            update.setChannel(channel);
                            
                            Map<String, PersistColumnProperties> map = new HashMap<>();
                            PersistColumnProperties pcp = new PersistColumnProperties();
                            pcp.setValue(reqId);
                            pcp.setColumnType(DataUnitColumnType.Long);
                            pcp.setPersistColumnSourceType(PersistColumnSourceType.DB_PK);
                            map.put("ReqID", pcp);
                            
                            pcp = new PersistColumnProperties();
                            pcp.setValue(32);
                            pcp.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
                            pcp.setColumnType(DataUnitColumnType.Int);
                            map.put("TransFlag", pcp);
                            
                            update.execute(persistContext);
                        }
                    }
                } catch (Exception ex) {
                    fault(operation);
                    logger.error(Contexts.getLogPrefix() + "fail to persist risk fact.", ex);
                } finally {
                    afterInvoke(operation);
                }
            }

            // 落地规则结果
            beforeInvoke("CardRiskDB.CheckResultLog.saveRuleResult");
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[保存CheckResultLog]");
                Long riskReqId = MapUtils.getLong(fact.ext, "reqId");
                if (riskReqId != null && riskReqId > 0) {
                    if (!Constants.eventPointsWithScene.contains(fact.eventPoint)) {
                        TraceLogger.traceLog("reqId = " + riskReqId);
                        saveRuleResult(riskReqId, fact.eventPoint, fact.results);
                    } else {
                        TraceLogger.traceLog("reqId = " + riskReqId + " [分场景]");
                        saveRuleResult(riskReqId, fact.eventPoint, fact.resultsGroupByScene);
                    }
                }
            } catch (Exception ex) {
                fault("CardRiskDB.CheckResultLog.saveRuleResult");
                logger.error(Contexts.getLogPrefix() + "保存规则执行结果至[InfoSecurity_CheckResultLog]表时发生异常.", ex);
            } finally {
                afterInvoke("CardRiskDB.CheckResultLog.saveRuleResult");
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
                    for (Entry<String, Map<String, Object>> entry : fact.results.entrySet()) {
                        
                        String ruleNo = entry.getKey();
                        int rLevel = NumberUtils.toInt(MapUtils.getString(entry.getValue(), Constants.riskLevel));
                        
                        if (rLevel > 0) {
                            RuleMonitorRepository.increaseCounter(fact.getEventPoint(), ruleNo);
                        }
                        
                    }
                    for (Entry<String, Map<String, Object>> entry : fact.resultsGroupByScene.entrySet()) {
                        
                        String ruleNo = entry.getKey();
                        int rLevel = NumberUtils.toInt(MapUtils.getString(entry.getValue(), Constants.riskLevel));
                        
                        if (rLevel > 0) {
                            RuleMonitorRepository.increaseCounter(fact.getEventPoint(), ruleNo);
                        }
                        
                    }
                } catch (Exception ex) {
                    logger.error(Contexts.getLogPrefix() + "RuleMonitorRepository increaseCounter fault.", ex);
                }
                
            }
        }
    }
    
    private void saveRuleResult(Long riskReqId, String eventPoint, Map<String, Map<String, Object>> results) throws DbExecuteException {
        RdbmsInsert insert = new RdbmsInsert();
        DistributionChannel channel = new DistributionChannel();
        channel.setChannelNo("CardRiskDB_INSERT_1");
        channel.setDatabaseType(DatabaseType.AllInOne_SqlServer);
        channel.setChannelDesc("CardRiskDB_INSERT_1");
        channel.setDatabaseURL("CardRiskDB_INSERT_1");
        insert.setChannel(channel);
        insert.setTable("InfoSecurity_CheckResultLog");

        /**
         * [LogID] = 主键 [ReqID] [RuleType] [RuleID] = 0 [RuleName] [RiskLevel]
         * [RuleRemark] [CreateDate] = now [DataChange_LastTime] = now
         * [IsHighlight] = 1
         */
        if (MapUtils.isNotEmpty(results)) {
            for (Entry<String, Map<String, Object>> entry : results.entrySet()) {
                try {
                    Long riskLevel = MapUtils.getLong(entry.getValue(), Constants.riskLevel);
                    Boolean isAsync = MapUtils.getBoolean(entry.getValue(), Constants.async);
                    if (riskLevel > 0) {
                        boolean withScene = Constants.eventPointsWithScene.contains(eventPoint);
                        if (withScene || isAsync) {
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
                            String ruleType = withScene ? (isAsync ? "SA" : "S") : (isAsync ? "NA" : "");
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
    
    private String resultToString(Map<String, Map<String, Object>> results) {
        List<String> result = Lists.newArrayList();
        if (MapUtils.isNotEmpty(results)) {
            for (Entry<String, Map<String, Object>> entry : results.entrySet()) {
                try {
                    Map<String, Object> val = entry.getValue();
                    if (val != null) {
                        Object level = val.get("riskLevel");
                        if (level != null) {
                            int riskLevel = Integer.valueOf(level.toString());
                            if (riskLevel > 0) {
                                result.add(entry.getKey());
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.error(Contexts.getLogPrefix() + "get risk level from results failed.", e);
                }
            }
        }
        return StringUtils.join(result, ',');
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
