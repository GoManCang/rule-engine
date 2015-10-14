/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.Constants;
import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.ModelRule;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.rulemonitor.RuleMonitorHelper;
import com.ctrip.infosec.configs.rulemonitor.RuleMonitorType;
import static com.ctrip.infosec.configs.utils.EventBodyUtils.valueAsString;
import com.ctrip.infosec.configs.utils.Threads;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.engine.StatelessModelRuleEngine;
import com.ctrip.infosec.sars.monitor.mq.SarsMqStatRepository;
import com.ctrip.infosec.sars.util.Collections3;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.annotation.PostConstruct;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 模型规则
 *
 * @author zhengby
 */
@Service
public class ModelRulesExecutorService {

    private static final Logger logger = LoggerFactory.getLogger(ModelRulesExecutorService.class);
    private LinkedBlockingQueue<RiskFact> queue = new LinkedBlockingQueue<>();

    /**
     * 执行模型规则
     */
    public RiskFact executeModelRules(RiskFact fact) {
        List<ModelRule> matchedRules = Configs.matchModelRules(fact);
        if (!matchedRules.isEmpty()) {
            try {
                fact.ext.put(Constants.key_traceLoggerParentTransId, TraceLogger.getTransId());
                queue.put(fact);
            } catch (InterruptedException ex) {
                // ignored
            }
        }
        return fact;
    }

    @PostConstruct
    public void dequeue() {
        int threads = 1;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        for (int i = 0; i < threads; i++) {
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    while (true) {
                        RiskFact fact = null;
                        beforeInvoke("ModelRules.execute");
                        try {
                            fact = queue.take();
                            TraceLogger.beginTrans(fact.eventId);
                            TraceLogger.setParentTransId(valueAsString(fact.ext, Constants.key_traceLoggerParentTransId));
                            fact.ext.remove(Constants.key_traceLoggerParentTransId);
                            execute(fact);
                        } catch (Exception ex) {
                            fault("ModelRules.execute");
                            logger.error("dequeue exception.", ex);
                        } finally {
                            afterInvoke("ModelRules.execute");
                            if (fact != null) {
                                TraceLogger.commitTrans();
                            }
                            Threads.sleep(10, TimeUnit.MILLISECONDS);
                        }
                    }
                }
            });
        }
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                int size = queue.size();
                if (size > 0) {
                    SarsMqStatRepository.put("MODEL_EXECUTE_QUEUE", size);
                    logger.warn("queue size: " + size);
                }
                int max = 10000;
                if (size > max) {
                    do {
                        RiskFact fact = queue.poll();
                        logger.warn("model queue is full. drop message: " + fact.eventId);
                    } while (queue.size() > max);
                }
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * 串行执行
     */
    public void execute(RiskFact fact) {

        // matchRules      
        List<ModelRule> matchedRules = Configs.matchModelRules(fact);
        List<String> scriptRulePackageNames = Collections3.extractToList(matchedRules, "ruleNo");
        logger.debug(Contexts.getLogPrefix() + "matched model rules: " + StringUtils.join(scriptRulePackageNames, ", "));
        TraceLogger.traceLog("匹配到 " + matchedRules.size() + " 条模型规则 ...");

        StatelessModelRuleEngine statelessModelRuleEngine = SpringContextHolder.getBean(StatelessModelRuleEngine.class);
        for (ModelRule rule : matchedRules) {
            RuleMonitorHelper.newTrans(fact, RuleMonitorType.MODEL_RULE, rule.getRuleNo());
            TraceLogger.beginNestedTrans(fact.eventId);
            TraceLogger.setNestedLogPrefix("[" + rule.getRuleNo() + "]");
            Contexts.setPolicyOrRuleNo(rule.getRuleNo());
            try {
                long start = System.currentTimeMillis();

                // add current execute ruleNo and logPrefix before execution
                fact.ext.put(Constants.key_ruleNo, rule.getRuleNo());
                fact.ext.put(Constants.key_isAsync, true);

                statelessModelRuleEngine.execute(rule.getRuleNo(), fact);

                // remove current execute ruleNo when finished execution.
                fact.ext.remove(Constants.key_ruleNo);
                fact.ext.remove(Constants.key_isAsync);

                long handlingTime = System.currentTimeMillis() - start;
                if (handlingTime > 100) {
                    logger.info(Contexts.getLogPrefix() + "modelRule: " + rule.getRuleNo() + ", usage: " + handlingTime + "ms");
                }

                Map<String, Object> result = fact.modelResults.get(rule.getRuleNo());
                if (result != null) {
                    int riskLevel = MapUtils.getIntValue(result, Constants.riskLevel, 0);
                    if (riskLevel > 0) {
                        TraceLogger.traceLog(">>>> [" + rule.getRuleNo() + "] 执行结果: [模型] riskLevel = " + result.get(Constants.riskLevel)
                                + ", riskMessage = " + result.get(Constants.riskMessage) + ", usage = " + result.get(Constants.timeUsage) + "ms");
                    }
                }

            } catch (Throwable ex) {
                logger.warn(Contexts.getLogPrefix() + "执行模型规则异常. modelRule: " + rule.getRuleNo(), ex);
                TraceLogger.traceLog("[" + rule.getRuleNo() + "] EXCEPTION: " + ex.toString());
            } finally {
                TraceLogger.commitNestedTrans();
                RuleMonitorHelper.commitTrans(fact);
                Contexts.clearLogPrefix();
            }
        }

    }
}
