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
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.converter.Converter;
import com.ctrip.infosec.rule.converter.ConverterLocator;
import com.ctrip.infosec.rule.converter.PreActionEnums;
import com.ctrip.infosec.rule.engine.StatelessPreRuleEngine;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.ctrip.infosec.sars.util.Collections3;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.google.common.collect.Lists;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
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
//        List<PreRule> matchedRules = Configs.matchPreRules(fact);
        List<PreRule> matchedRules = Configs.matchPreRulesInRules(fact, isAsync);
        List<String> ruleNos = Collections3.extractToList(matchedRules, "ruleNo");
        logger.info(Contexts.getLogPrefix() + "matched pre rules: " + StringUtils.join(ruleNos, ", "));
        TraceLogger.traceLog("匹配到 " + ruleNos.size() + " 条预处理规则 ...");

        if (isAsync) {
            executeSerial(fact, matchedRules);
        } else {
            executeParallel(fact, matchedRules);
        }

//        StatelessPreRuleEngine statelessPreRuleEngine = SpringContextHolder.getBean(StatelessPreRuleEngine.class);
//
//        // 先执行脚、后执行可视化
//        for (PreRule rule : matchedRules) {
//            // 脚本
//            if (rule.getRuleType() == RuleType.Script) {
//                long start = System.currentTimeMillis();
//                try {
//                    // add current execute logPrefix before execution
//                    fact.ext.put(Constants.key_logPrefix, SarsMonitorContext.getLogPrefix());
//
//                    TraceLogger.traceLog("[" + rule.getRuleNo() + "]");
//                    statelessPreRuleEngine.execute(rule.getRuleNo(), fact);
//
//                    // remove current execute ruleNo when finished execution.
//                    fact.ext.remove(Constants.key_logPrefix);
//                } catch (Throwable ex) {
//                    logger.warn(Contexts.getLogPrefix() + "invoke stateless pre rule failed. preRule: " + rule.getRuleNo(), ex);
//                }
//                long handlingTime = System.currentTimeMillis() - start;
//                if (handlingTime > 50) {
//                    logger.info(Contexts.getLogPrefix() + "preRule: " + rule.getRuleNo() + ", usage: " + handlingTime + "ms");
//                }
//                TraceLogger.traceLog("[" + rule.getRuleNo() + "] usage: " + handlingTime + "ms");
//            }
//        }
//        for (PreRule rule : matchedRules) {
//            if (rule.getRuleType() == RuleType.Visual) {
//                long start = System.currentTimeMillis();
//                // 执行可视化预处理
//                PreActionEnums preAction = PreActionEnums.parse(rule.getPreAction());
//                if (preAction != null) {
//                    try {
//                        TraceLogger.traceLog("[" + rule.getRuleNo() + "]");
//                        Converter converter = converterLocator.getConverter(preAction);
//                        converter.convert(preAction, rule.getPreActionFieldMapping(), fact, rule.getPreActionResultWrapper());
//                    } catch (Exception ex) {
//                        logger.warn(Contexts.getLogPrefix() + "invoke visual pre rule failed. ruleNo: " + rule.getRuleNo() + ", exception: " + ex.getMessage());
//                        TraceLogger.traceLog("[" + rule.getRuleNo() + "] EXCEPTION: " + ex.toString());
//                    }
//                }
//                long handlingTime = System.currentTimeMillis() - start;
//                if (handlingTime > 50) {
//                    logger.info(Contexts.getLogPrefix() + "preRule: " + rule.getRuleNo() + ", usage: " + handlingTime + "ms");
//                }
//                TraceLogger.traceLog("[" + rule.getRuleNo() + "] usage: " + handlingTime + "ms");
//            }
//        }
    }

    /**
     * 串行执行
     */
    void executeSerial(RiskFact fact, List<PreRule> matchedRules) {

        StatelessPreRuleEngine statelessPreRuleEngine = SpringContextHolder.getBean(StatelessPreRuleEngine.class);

        // 先执可视化、后执行行脚
        for (PreRule rule : matchedRules) {
            if (rule.getRuleType() == RuleType.Visual) {
                String _nestedTransId = TraceLogger.beginNestedTrans(fact.eventId);
                TraceLogger.setNestedLogPrefix(_nestedTransId, "[" + rule.getRuleNo() + "]");
                long start = System.currentTimeMillis();
                // 执行可视化预处理
                PreActionEnums preAction = PreActionEnums.parse(rule.getPreAction());
                if (preAction != null) {
                    try {
                        Converter converter = converterLocator.getConverter(preAction);
                        converter.convert(preAction, rule.getPreActionFieldMapping(), fact, rule.getPreActionResultWrapper());
                    } catch (Exception ex) {
                        logger.warn(Contexts.getLogPrefix() + "invoke visual pre rule failed. ruleNo: " + rule.getRuleNo() + ", exception: " + ex.getMessage());
                        TraceLogger.traceLog("[" + rule.getRuleNo() + "] EXCEPTION: " + ex.toString());
                    }
                }
                long handlingTime = System.currentTimeMillis() - start;
                if (handlingTime > 50) {
                    logger.info(Contexts.getLogPrefix() + "preRule: " + rule.getRuleNo() + ", usage: " + handlingTime + "ms");
                }
                TraceLogger.traceNestedLog(_nestedTransId, "[" + rule.getRuleNo() + "] usage: " + handlingTime + "ms");
            }
        }
        for (PreRule rule : matchedRules) {
            // 脚本
            if (rule.getRuleType() == RuleType.Script) {
                String _nestedTransId = TraceLogger.beginNestedTrans(fact.eventId);
                TraceLogger.setNestedLogPrefix(_nestedTransId, "[" + rule.getRuleNo() + "]");
                long start = System.currentTimeMillis();
                try {
                    // add current execute logPrefix before execution
                    fact.ext.put(Constants.key_logPrefix, SarsMonitorContext.getLogPrefix());

                    statelessPreRuleEngine.execute(rule.getRuleNo(), fact);

                    // remove current execute ruleNo when finished execution.
                    fact.ext.remove(Constants.key_logPrefix);
                } catch (Throwable ex) {
                    logger.warn(Contexts.getLogPrefix() + "invoke stateless pre rule failed. preRule: " + rule.getRuleNo(), ex);
                }
                long handlingTime = System.currentTimeMillis() - start;
                if (handlingTime > 50) {
                    logger.info(Contexts.getLogPrefix() + "preRule: " + rule.getRuleNo() + ", usage: " + handlingTime + "ms");
                }
                TraceLogger.traceNestedLog(_nestedTransId, "[" + rule.getRuleNo() + "] usage: " + handlingTime + "ms");
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
        List runs2 = Lists.newArrayList();
        for (PreRule rule : matchedRules) {

            final String packageName = rule.getRuleNo();

            // 脚本
            if (rule.getRuleType() == RuleType.Script) {

                runs1.add(new Callable<RiskFact>() {

                    @Override
                    public RiskFact call() throws Exception {
                        TraceLogger.beginTrans(fact.eventId);
                        TraceLogger.setParentTransId(_traceLoggerParentTransId);
                        TraceLogger.setLogPrefix("[" + packageName + "]");
                        long start = System.currentTimeMillis();
                        try {
                            // 执行预处理脚本
                            statelessPreRuleEngine.execute(packageName, fact);

                            long handlingTime = System.currentTimeMillis() - start;
                            if (handlingTime > 50) {
                                logger.info(_logPrefix + "preRule: " + packageName + ", usage: " + handlingTime + "ms");
                            }
                            TraceLogger.traceLog("[" + packageName + "] usage: " + handlingTime + "ms");
                        } catch (Throwable ex) {
                            logger.warn(_logPrefix + "invoke stateless pre rule failed. preRule: " + packageName, ex);
                        } finally {
                            TraceLogger.commitTrans();
                        }
                        return null;
                    }

                });

            } else if (rule.getRuleType() == RuleType.Visual) {

                final PreActionEnums preAction = PreActionEnums.parse(rule.getPreAction());
                final Map<String, String> preActionFieldMapping = rule.getPreActionFieldMapping();
                final String preActionResultWrapper = rule.getPreActionResultWrapper();

                runs2.add(new Callable<RiskFact>() {

                    @Override
                    public RiskFact call() throws Exception {
                        TraceLogger.beginTrans(fact.eventId);
                        TraceLogger.setParentTransId(_traceLoggerParentTransId);
                        TraceLogger.setLogPrefix("[" + packageName + "]");
                        // 执行可视化预处理
                        long start = System.currentTimeMillis();
                        try {
                            if (preAction != null) {
                                Converter converter = converterLocator.getConverter(preAction);
                                converter.convert(preAction, preActionFieldMapping, fact, preActionResultWrapper);

                                long handlingTime = System.currentTimeMillis() - start;
                                if (handlingTime > 50) {
                                    logger.info(Contexts.getLogPrefix() + "preRule: " + packageName + ", usage: " + handlingTime + "ms");
                                }
                                TraceLogger.traceLog("[" + packageName + "] usage: " + handlingTime + "ms");
                            }
                        } catch (Exception ex) {
                            logger.warn(_logPrefix + "invoke visual pre rule failed. ruleNo: " + packageName + ", exception: " + ex.getMessage());
                            TraceLogger.traceLog("EXCEPTION: " + ex.toString());
                        } finally {
                            TraceLogger.commitTrans();
                        }
                        return null;
                    }

                });
            }

        }

        // run
        try {
            if (!runs2.isEmpty()) {
                ParallelExecutorHolder.excutor.invokeAll(runs2, timeout, TimeUnit.SECONDS);
            }
            if (!runs1.isEmpty()) {
                ParallelExecutorHolder.excutor.invokeAll(runs1, timeout, TimeUnit.SECONDS);
            }
        } catch (Exception ex) {
            // ignored
        }
    }
}
