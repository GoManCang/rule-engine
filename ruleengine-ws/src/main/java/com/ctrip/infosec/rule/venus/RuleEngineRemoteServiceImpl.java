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
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.executor.EventDataMergeService;
import com.ctrip.infosec.rule.executor.PostRulesExecutorService;
import com.ctrip.infosec.rule.executor.PreRulesExecutorService;
import com.ctrip.infosec.rule.executor.RulesExecutorService;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
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

    @Override
    public RiskFact verify(RiskFact fact) {
        beforeInvoke();
        logger.info("VENUS: fact=" + JSON.toJSONString(fact));
        Contexts.setLogPrefix("[" + fact.eventPoint + "][" + fact.eventId + "] ");
        SarsMonitorContext.setLogPrefix(Contexts.getLogPrefix());
        try {
            // 执行Redis读取
            eventDataMergeService.executeRedisGet(fact);
            // 执行预处理
            preRulesExecutorService.executePreRules(fact, false);
            //执行推送数据到Redis
            eventDataMergeService.executeRedisPut(fact);
            // 执行同步规则
            rulesExecutorService.executeSyncRules(fact);
        } catch (Throwable ex) {
            fault();
            if (fact.finalResult == null) {
                fact.setFinalResult(Constants.defaultResult);
            }
            logger.error(Contexts.getLogPrefix() + "invoke verify exception.", ex);
        } finally {
            afterInvoke("RuleEngineRemoteService.verify");
        }
        return fact;
    }

}
