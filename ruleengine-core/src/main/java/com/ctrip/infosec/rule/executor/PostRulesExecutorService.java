/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.PostRule;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.engine.StatelessPostRuleEngine;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.ctrip.infosec.sars.util.Collections3;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 *
 * @author zhengby
 */
@Service
public class PostRulesExecutorService {

    private static final Logger logger = LoggerFactory.getLogger(PostRulesExecutorService.class);

    /**
     * 执行预处理规则
     */
    public RiskFact executePostRules(RiskFact fact, boolean isAsync) {
        execute(fact, isAsync);
        return fact;
    }

    /**
     * 串行执行
     */
    void execute(RiskFact fact, boolean isAsync) {

        // matchRules      
        List<PostRule> matchedRules = Configs.matchPostRules(fact);
        List<String> scriptRulePackageNames = Collections3.extractToList(matchedRules, "ruleNo");
        logger.info(Contexts.getLogPrefix() + "matched post rules: " + StringUtils.join(scriptRulePackageNames, ", "));
        TraceLogger.traceLog("匹配到 " + matchedRules.size() + " 条后处理规则 ...");

        StatelessPostRuleEngine statelessPostRuleEngine = SpringContextHolder.getBean(StatelessPostRuleEngine.class);
        for (PostRule rule : matchedRules) {
            String _nestedTransId = TraceLogger.beginNestedTrans(fact.eventId);
            TraceLogger.setNestedLogPrefix(_nestedTransId, "[" + rule.getRuleNo() + "]");
            long start = System.currentTimeMillis();
            try {
                // add current execute logPrefix before execution
                fact.ext.put(Constants.key_logPrefix, SarsMonitorContext.getLogPrefix());

                statelessPostRuleEngine.execute(rule.getRuleNo(), fact);

                // remove current execute ruleNo when finished execution.
                fact.ext.remove(Constants.key_logPrefix);
            } catch (Throwable ex) {
                logger.warn(Contexts.getLogPrefix() + "invoke stateless post rule failed. postRule: " + rule.getRuleNo(), ex);
            }
            long handlingTime = System.currentTimeMillis() - start;
            if (handlingTime > 50) {
                logger.info(Contexts.getLogPrefix() + "postRule: " + rule.getRuleNo() + ", usage: " + handlingTime + "ms");
            }
            TraceLogger.traceNestedLog(_nestedTransId, "[" + rule.getRuleNo() + "] usage: " + handlingTime + "ms");
        }

//        StopWatch clock = new StopWatch();
//        try {
//            clock.reset();
//            clock.start();
//
//            // add current execute logPrefix before execution
//            fact.ext.put(Constants.key_logPrefix, SarsMonitorContext.getLogPrefix());
//            fact.ext.put(Constants.key_traceLoggerParentTransId, TraceLogger.getTransId());
//
//            // TODO: 需要判断ruleType == Script
//            statelessPostRuleEngine.execute(scriptRulePackageNames, fact);
//
//            // remove current execute ruleNo when finished execution.
//            fact.ext.remove(Constants.key_logPrefix);
//            fact.ext.remove(Constants.key_traceLoggerParentTransId);
//
//            clock.stop();
//            long handlingTime = clock.getTime();
//            if (handlingTime > 50) {
//                logger.info(Contexts.getLogPrefix() + "postRules: " + scriptRulePackageNames + ", usage: " + handlingTime + "ms");
//            }
//
//        } catch (Throwable ex) {
//            logger.warn(Contexts.getLogPrefix() + "invoke stateless post rule failed. packageNames: " + scriptRulePackageNames, ex);
//        }
    }
}
