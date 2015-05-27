/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.PreRule;
import com.ctrip.infosec.configs.event.RuleType;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.converter.Converter;
import com.ctrip.infosec.rule.converter.ConverterLocator;
import com.ctrip.infosec.rule.converter.PreActionEnums;
import com.ctrip.infosec.rule.engine.StatelessPreRuleEngine;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.google.common.collect.Lists;
import java.util.List;
import org.apache.commons.lang3.time.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 *
 * @author zhengby
 */
@Service
public class PreRulesExecutorService {

    private static final Logger logger = LoggerFactory.getLogger(PreRulesExecutorService.class);
    @Autowired
    private ConverterLocator converterLocator;

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
//        List<PreRule> matchedRules = Configs.matchPreRules(fact);
    	List<PreRule> matchedRules = Configs.matchPreRulesInRules(fact);
        List<String> scriptRulePackageNames = Lists.newArrayList();
        for (PreRule rule : matchedRules) {
            if (rule.getRuleType() == RuleType.Visual) {
                // 执行可视化预处理
                PreActionEnums preAction = PreActionEnums.parse(rule.getPreAction());
                if (preAction != null) {
                    try {
                        Converter converter = converterLocator.getConverter(preAction);
                        converter.convert(preAction, rule.getPreActionFieldMapping(), fact, rule.getPreActionResultWrapper());
                    } catch (Exception ex) {
                        logger.warn(Contexts.getLogPrefix() + "invoke visual pre rule failed. ruleNo: " + rule.getRuleNo() + ", exception: " + ex.getMessage());
                    }
                }
            } else if (rule.getRuleType() == RuleType.Script) {
                scriptRulePackageNames.add(rule.getRuleNo());
            }
        }
        logger.info(Contexts.getLogPrefix() + "matched pre rules: " + scriptRulePackageNames.size());
        StatelessPreRuleEngine statelessPreRuleEngine = SpringContextHolder.getBean(StatelessPreRuleEngine.class);

        StopWatch clock = new StopWatch();
        try {
            clock.reset();
            clock.start();

            // add current execute logPrefix before execution
            fact.ext.put(Constants.key_logPrefix, SarsMonitorContext.getLogPrefix());

            statelessPreRuleEngine.execute(scriptRulePackageNames, fact);

            // remove current execute ruleNo when finished execution.
            fact.ext.remove(Constants.key_logPrefix);

            clock.stop();
            long handlingTime = clock.getTime();
            if (handlingTime > 50) {
                logger.info(Contexts.getLogPrefix() + "preRules: " + scriptRulePackageNames + ", usage: " + handlingTime + "ms");
            }

        } catch (Throwable ex) {
            logger.warn(Contexts.getLogPrefix() + "invoke stateless pre rule failed. packageNames: " + scriptRulePackageNames, ex);
        }
    }
}
