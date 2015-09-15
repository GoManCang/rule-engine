/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.PreRule;
import com.ctrip.infosec.configs.event.PreRuleTreeNode;
import com.ctrip.infosec.configs.event.RuleType;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.rulemonitor.RuleMonitorHelper;
import com.ctrip.infosec.configs.rulemonitor.RuleMonitorType;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.converter.Converter;
import com.ctrip.infosec.rule.converter.ConverterLocator;
import com.ctrip.infosec.rule.converter.PreActionEnums;
import com.ctrip.infosec.rule.engine.StatelessPreRuleEngine;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.google.common.collect.Lists;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
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
    // 秒
    private int timeout = GlobalConfig.getInteger("PreRules.executor.timeout", 1);

    /**
     * 执行预处理规则
     */
    public RiskFact executePreRules(RiskFact fact, boolean isAsync) {
        execute(fact, isAsync);
        return fact;
    }

    /**
     * 串行执行
     */
    void execute(RiskFact fact, boolean isAsync) {
        // matchRules      
//        List<PreRule> matchedRules = Configs.matchPreRulesInRules(fact, isAsync);
//        List<String> ruleNos = Collections3.extractToList(matchedRules, "ruleNo");
//        logger.debug(Contexts.getLogPrefix() + "matched pre rules: " + StringUtils.join(ruleNos, ", "));
//        TraceLogger.traceLog("匹配到 " + ruleNos.size() + " 条预处理规则 ...");

        List<PreRuleTreeNode> matchedPreRuleTree = Configs.matchPreRuleTree(fact, isAsync);

        TraceLogger.traceLog("开始执行预处理规则 ...");
        boolean hasChildren = true;
        while (hasChildren) {
            List<PreRule> matchedRules = Lists.newArrayList();
            List<PreRuleTreeNode> children = Lists.newArrayList();
            for (PreRuleTreeNode node : matchedPreRuleTree) {
                matchedRules.add(node.getData());
                if (node.getNodes() != null && !node.getNodes().isEmpty()) {
                    children.addAll(node.getNodes());
                }
            }

            if (isAsync) {
                executeSerial(fact, matchedRules);
            } else {
                executeParallel(fact, matchedRules);
            }

            if (children.isEmpty()) {
                hasChildren = false;
            }
        }

    }

    /**
     * 串行执行
     */
    void executeSerial(RiskFact fact, List<PreRule> matchedRules) {

        StatelessPreRuleEngine statelessPreRuleEngine = SpringContextHolder.getBean(StatelessPreRuleEngine.class);

        // 先执可视化、后执行行脚
        for (PreRule rule : matchedRules) {
            // 匹配前置条件
            boolean matched = Configs.match(rule.getConditions(), rule.getConditionsLogical(), fact.eventBody);
            if (!matched) {
                continue;
            }

            RuleMonitorHelper.newTrans(fact, RuleMonitorType.PRE_RULE, rule.getRuleNo());
            TraceLogger.beginNestedTrans(fact.eventId);
            TraceLogger.setNestedLogPrefix("[" + rule.getRuleNo() + "]");
            Contexts.setPolicyOrRuleNo(rule.getRuleNo());
            long start = System.currentTimeMillis();
            // 执行规则
            try {
                if (rule.getRuleType() == RuleType.Visual) {
                    PreActionEnums preAction = PreActionEnums.parse(rule.getPreAction());
                    if (preAction != null) {
                        Converter converter = converterLocator.getConverter(preAction);
                        converter.convert(preAction, rule.getPreActionFieldMapping(), fact, rule.getPreActionResultWrapper(), true);
                    }
                } else if (rule.getRuleType() == RuleType.Script) {
                    statelessPreRuleEngine.execute(rule.getRuleNo(), fact);
                }
            } catch (Exception ex) {
                logger.warn(Contexts.getLogPrefix() + "执行预处理规则异常. preRule: " + rule.getRuleNo() + ", exception: " + ex.getMessage());
                TraceLogger.traceLog("[" + rule.getRuleNo() + "] EXCEPTION: " + ex.toString());
            } finally {
                long handlingTime = System.currentTimeMillis() - start;
                if (handlingTime > 100) {
                    logger.info(Contexts.getLogPrefix() + "preRule: " + rule.getRuleNo() + ", usage: " + handlingTime + "ms");
                }
                TraceLogger.traceLog("[" + rule.getRuleNo() + "] usage: " + handlingTime + "ms");
                TraceLogger.commitNestedTrans();
                RuleMonitorHelper.commitTrans(fact);
                Contexts.clearLogPrefix();
            }
        }
    }

    /**
     * 并行执行
     */
    void executeParallel(final RiskFact fact, List<PreRule> matchedRules) {

        final StatelessPreRuleEngine statelessPreRuleEngine = SpringContextHolder.getBean(StatelessPreRuleEngine.class);
        final String _logPrefix = Contexts.getLogPrefix();
        final String _traceLoggerParentTransId = TraceLogger.getTransId();

        List runs1 = Lists.newArrayList();
        for (final PreRule rule : matchedRules) {

            // 匹配前置条件
            boolean matched = Configs.match(rule.getConditions(), rule.getConditionsLogical(), fact.eventBody);
            if (!matched) {
                continue;
            }

            final String packageName = rule.getRuleNo();
            runs1.add(new Callable<Boolean>() {

                @Override
                public Boolean call() throws Exception {
                    RuleMonitorHelper.newTrans(fact, RuleMonitorType.PRE_RULE, packageName);
                    TraceLogger.beginTrans(fact.eventId);
                    TraceLogger.setParentTransId(_traceLoggerParentTransId);
                    TraceLogger.setLogPrefix("[" + packageName + "]");
                    Contexts.setPolicyOrRuleNo(packageName);
                    long start = System.currentTimeMillis();
                    try {
                        if (rule.getRuleType() == RuleType.Script) {
                            statelessPreRuleEngine.execute(packageName, fact);
                        } else if (rule.getRuleType() == RuleType.Visual) {
                            PreActionEnums preAction = PreActionEnums.parse(rule.getPreAction());
                            if (preAction != null) {
                                Converter converter = converterLocator.getConverter(preAction);
                                converter.convert(preAction, rule.getPreActionFieldMapping(), fact, rule.getPreActionResultWrapper(), false);
                            }
                        }
                    } catch (Throwable ex) {
                        logger.warn(_logPrefix + "执行预处理规则异常. preRule: " + packageName, ex);
                        TraceLogger.traceLog("EXCEPTION: " + ex.toString());
                    } finally {
                        long handlingTime = System.currentTimeMillis() - start;
                        if (handlingTime > 100) {
                            logger.info(_logPrefix + "preRule: " + packageName + ", usage: " + handlingTime + "ms");
                        }
                        TraceLogger.traceLog("[" + packageName + "] usage: " + handlingTime + "ms");
                        TraceLogger.commitTrans();
                        RuleMonitorHelper.commitTrans2Trunk(fact);
                        Contexts.clearLogPrefix();
                    }
                    return true;
                }
            });

        }

        // run
        try {
            if (!runs1.isEmpty()) {
                ParallelExecutorHolder.excutor.invokeAll(runs1, timeout, TimeUnit.SECONDS);
            }
        } catch (Exception ex) {
            // ignored
        }
    }
}
