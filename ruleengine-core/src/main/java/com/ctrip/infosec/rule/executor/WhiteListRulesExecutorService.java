/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.WhitelistRule;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.engine.StatelessWhitelistRuleEngine;
import com.ctrip.infosec.sars.util.Collections3;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 白名单规则
 *
 * @author zhengby
 */
@Service
public class WhiteListRulesExecutorService {

    private static final Logger logger = LoggerFactory.getLogger(WhiteListRulesExecutorService.class);

    /**
     * 执行白名单规则
     */
    public RiskFact executeWhitelistRules(RiskFact fact) {
        execute(fact);
        return fact;
    }

    /**
     * 串行执行
     */
    void execute(RiskFact fact) {

        // matchRules      
        List<WhitelistRule> matchedRules = Configs.matchWhitelistRules(fact);
        List<String> scriptRulePackageNames = Collections3.extractToList(matchedRules, "ruleNo");
        logger.debug(Contexts.getLogPrefix() + "matched whitelist rules: " + StringUtils.join(scriptRulePackageNames, ", "));
        TraceLogger.traceLog("匹配到 " + matchedRules.size() + " 条黑白名单规则 ...");

        StatelessWhitelistRuleEngine statelessWhitelistRuleEngine = SpringContextHolder.getBean(StatelessWhitelistRuleEngine.class);
        for (WhitelistRule rule : matchedRules) {
            TraceLogger.beginNestedTrans(fact.eventId);
            TraceLogger.setNestedLogPrefix("[" + rule.getRuleNo() + "]");
            Contexts.setPolicyOrRuleNo(rule.getRuleNo());
            try {
                long start = System.currentTimeMillis();

                // add current execute ruleNo and logPrefix before execution
                fact.ext.put(Constants.key_ruleNo, rule.getRuleNo());
                fact.ext.put(Constants.key_isAsync, false);

                statelessWhitelistRuleEngine.execute(rule.getRuleNo(), fact);

                // remove current execute ruleNo when finished execution.
                fact.ext.remove(Constants.key_ruleNo);
                fact.ext.remove(Constants.key_isAsync);

                long handlingTime = System.currentTimeMillis() - start;
                if (handlingTime > 100) {
                    logger.info(Contexts.getLogPrefix() + "whitelistRule: " + rule.getRuleNo() + ", usage: " + handlingTime + "ms");
                }

                if (fact.finalWhitelistResult.isEmpty()) {
                    TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + rule.getRuleNo() + "] 没有命中白名单. usage: " + handlingTime + "ms");
                } else {
                    TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + rule.getRuleNo() + "] 命中白名单: riskLevel = " + fact.finalWhitelistResult.get(Constants.riskLevel)
                            + ", riskMessage = " + fact.finalWhitelistResult.get(Constants.riskMessage) + ", usage = " + fact.finalWhitelistResult.get(Constants.timeUsage) + "ms");
                }

            } catch (Throwable ex) {
                logger.warn(Contexts.getLogPrefix() + "invoke stateless whitelist rule failed. whitelistRule: " + rule.getRuleNo(), ex);
                TraceLogger.traceLog("[" + rule.getRuleNo() + "] EXCEPTION: " + ex.toString());
            } finally {
                TraceLogger.commitNestedTrans();
                Contexts.clearLogPrefix();
            }
        }

    }
}
