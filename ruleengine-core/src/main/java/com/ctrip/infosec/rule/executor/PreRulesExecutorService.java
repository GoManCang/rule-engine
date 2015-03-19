/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.PreRule;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.engine.StatelessPreRuleEngine;
import com.ctrip.infosec.sars.util.Collections3;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import java.util.List;
import org.apache.commons.lang3.time.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 *
 * @author zhengby
 */
@Service
public class PreRulesExecutorService {

    private static final Logger logger = LoggerFactory.getLogger(PreRulesExecutorService.class);

    /**
     * 执行预处理规则
     */
    public RiskFact executePreRules(RiskFact fact, boolean isAsync) {
        execute(fact, false);
        return fact;
    }

    /**
     * 串行执行
     */
    void execute(RiskFact fact, boolean isAsync) {

        // matchRules      
        List<PreRule> matchedRules = Configs.matchPreRules(fact, isAsync);
        List<String> packageNames = Collections3.extractToList(matchedRules, "ruleNo");
        logger.info(Contexts.getLogPrefix() + "matched pre rules: " + packageNames.size());
        StatelessPreRuleEngine statelessPreRuleEngine = SpringContextHolder.getBean(StatelessPreRuleEngine.class);

        StopWatch clock = new StopWatch();
        try {
            clock.reset();
            clock.start();

            statelessPreRuleEngine.execute(packageNames, fact);

            clock.stop();
            long handlingTime = clock.getTime();
            if (handlingTime > 50) {
                logger.info(Contexts.getLogPrefix() + "preRules: " + packageNames + ", usage: " + handlingTime + "ms");
            }

        } catch (Throwable ex) {
            logger.warn(Contexts.getLogPrefix() + "invoke stateless pre rule failed. packageNames: " + packageNames, ex);
        }
    }
}
