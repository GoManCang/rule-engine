/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.venus;

import com.ctrip.infosec.common.Constants;
import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.executor.EventDataMergeService;
import com.ctrip.infosec.rule.executor.PostRulesExecutorService;
import com.ctrip.infosec.rule.executor.PreRulesExecutorService;
import com.ctrip.infosec.rule.executor.RulesExecutorService;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import org.apache.commons.collections.MapUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 *
 * @author zhengby
 */
public class RuleEngineRemoteServiceImpl implements RuleEngineRemoteService {

    private static Logger logger = LoggerFactory.getLogger(RuleEngineRemoteServiceImpl.class);

    @Autowired
    private RulesExecutorService rulesExecutorService;
    @Autowired
    private PreRulesExecutorService preRulesExecutorService;
    @Autowired
    private EventDataMergeService eventDataMergeService;
    @Autowired
    private PostRulesExecutorService postRulesExecutorService;

    /**
     * 复杂嵌套JSON可能导致OOM, 慎用
     */
    @Override
    public RiskFact verify(RiskFact fact) {
        beforeInvoke();
        logger.info("VENUS: fact=" + JSON.toJSONString(fact));
        Contexts.setLogPrefix("[" + fact.eventPoint + "][" + fact.eventId + "] ");
        SarsMonitorContext.setLogPrefix(Contexts.getLogPrefix());

        boolean traceLoggerEnabled = MapUtils.getBoolean(fact.ext, Constants.key_traceLogger, true);
        TraceLogger.enabled(traceLoggerEnabled);

        try {
            // 执行Redis读取
            eventDataMergeService.executeRedisGet(fact);
            // 执行预处理            
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[同步预处理]");
                preRulesExecutorService.executePreRules(fact, false);
            } finally {
                TraceLogger.commitTrans();
            }
            //执行推送数据到Redis
            eventDataMergeService.executeRedisPut(fact);
            // 执行同步规则
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[同步规则]");
                rulesExecutorService.executeSyncRules(fact);
            } finally {
                TraceLogger.commitTrans();
            }
            // 执行后处理
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[同步后处理]");
                postRulesExecutorService.executePostRules(fact, false);
            } finally {
                TraceLogger.commitTrans();
            }
        } catch (Throwable ex) {
            fault();
            if (fact.finalResult == null) {
                fact.setFinalResult(Constants.defaultResult);
            }
            logger.error(Contexts.getLogPrefix() + "invoke verify exception.", ex);
        } finally {
            afterInvoke("RuleEngine.verify");
        }
        return fact;
    }

    @Override
    public String execute(String factTxt) {
        beforeInvoke();
        logger.info("VENUS: fact=" + factTxt);
        RiskFact fact = JSON.parseObject(factTxt, RiskFact.class);
        Contexts.setLogPrefix("[" + fact.eventPoint + "][" + fact.eventId + "] ");
        SarsMonitorContext.setLogPrefix(Contexts.getLogPrefix());

        boolean traceLoggerEnabled = MapUtils.getBoolean(fact.ext, Constants.key_traceLogger, true);
        TraceLogger.enabled(traceLoggerEnabled);

        try {
            // 执行Redis读取
            eventDataMergeService.executeRedisGet(fact);
            // 执行预处理            
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[同步预处理]");
                preRulesExecutorService.executePreRules(fact, false);
            } finally {
                TraceLogger.commitTrans();
            }
            //执行推送数据到Redis
            eventDataMergeService.executeRedisPut(fact);
            // 执行同步规则
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[同步规则]");
                rulesExecutorService.executeSyncRules(fact);
            } finally {
                TraceLogger.commitTrans();
            }
            // 执行后处理
            try {
                TraceLogger.beginTrans(fact.eventId);
                TraceLogger.setLogPrefix("[同步后处理]");
                postRulesExecutorService.executePostRules(fact, false);
            } finally {
                TraceLogger.commitTrans();
            }
        } catch (Throwable ex) {
            fault();
            if (fact.finalResult == null) {
                fact.setFinalResult(Constants.defaultResult);
            }
            logger.error(Contexts.getLogPrefix() + "invoke execute exception.", ex);
        } finally {
            afterInvoke("RuleEngine.execute");
        }
        return JSON.toJSONString(fact);
    }

}
