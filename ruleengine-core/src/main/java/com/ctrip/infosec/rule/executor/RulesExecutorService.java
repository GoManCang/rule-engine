/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.Rule;
import com.ctrip.infosec.configs.utils.BeanMapper;
import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.engine.StatelessRuleEngine;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 使用线程池并行执行规则
 *
 * @author zhengby
 */
@Service
public class RulesExecutorService {

    private static final Logger logger = LoggerFactory.getLogger(RulesExecutorService.class);
    private ThreadPoolExecutor excutor = new ThreadPoolExecutor(64, 512, 60, TimeUnit.SECONDS, new SynchronousQueue(), new ThreadPoolExecutor.CallerRunsPolicy());

    /**
     * 执行同步规则
     */
    public RiskFact executeSyncRules(RiskFact fact) {
        logger.info(Contexts.getLogPrefix() + "execute sync rules ...");
        if (fact.results == null) {
            fact.setResults(new HashMap<String, Map<String, Object>>());
        }
        if (fact.ext == null) {
            fact.setExt(new HashMap<String, Object>());
        }
        executeParallel(fact);

        // 返回结果
        Map<String, Object> finalResult = Constants.defaultResult;
        for (Map<String, Object> rs : fact.results.values()) {
            List<String> sceneList = (List) rs.get(Constants.riskScene);
            if (sceneList == null || sceneList.isEmpty()) {
                finalResult = compareAndReturn(finalResult, rs);
            } else {

                for (String scene : sceneList) {
                    int riskLevel = MapUtils.getInteger(rs, Constants.riskLevel, 0);
                    String riskMessage = MapUtils.getString(rs, Constants.riskMessage, "");

                    //按scene分 往data中push最高分数的风险信息 
                    Map<String, Object> currentSceneMap = fact.finalResultGroupByScene.get(scene);
                    if (null == currentSceneMap) {
                        currentSceneMap = new HashMap<String, Object>();
                        currentSceneMap.put(Constants.riskLevel, riskLevel);
                        currentSceneMap.put(Constants.riskMessage, riskMessage);
                        fact.getFinalResultGroupByScene().put(scene, currentSceneMap);
                    } else {
                        int currentRiskLevel = MapUtils.getInteger(currentSceneMap, Constants.riskLevel, 0);

                        //比较risklevel,最高的存到当前的scene map中
                        if (riskLevel > currentRiskLevel) {
                            currentSceneMap.put(Constants.riskLevel, riskLevel);
                            currentSceneMap.put(Constants.riskMessage, riskMessage);
                        }
                    }
                }
            }
        }
        for (Map<String, Object> rs : fact.finalResultGroupByScene.values()) {
            finalResult = compareAndReturn(finalResult, rs);
        }
        fact.setFinalResult(
                ImmutableMap.of(
                        Constants.riskLevel, finalResult.get(Constants.riskLevel),
                        Constants.riskMessage, finalResult.get(Constants.riskMessage)
                ));
        logger.info(Contexts.getLogPrefix() + "execute sync rules finished. finalResult: riskLevel="
                + finalResult.get(Constants.riskLevel) + ", riskMessage=" + finalResult.get(Constants.riskMessage));
        TraceLogger.traceLog("执行同步规则完成. finalResult: riskLevel="
                + finalResult.get(Constants.riskLevel) + ", riskMessage=" + finalResult.get(Constants.riskMessage));
        return fact;
    }

    /**
     * 执行异步规则
     */
    public RiskFact executeAsyncRules(RiskFact fact) {
        logger.info(Contexts.getLogPrefix() + "execute async rules ...");
        if (fact.results == null) {
            fact.setResults(new HashMap<String, Map<String, Object>>());
        }
        if (fact.ext == null) {
            fact.setExt(new HashMap<String, Object>());
        }
        executeSerial(fact);

        // 返回结果
        Map<String, Object> finalResult = Constants.defaultResult;
        for (Map<String, Object> rs : fact.results.values()) {
            List<String> sceneList = (List) rs.get(Constants.riskScene);
            if (sceneList == null || sceneList.isEmpty()) {
                finalResult = compareAndReturn(finalResult, rs);
            } else {

                for (String scene : sceneList) {
                    int riskLevel = MapUtils.getInteger(rs, Constants.riskLevel, 0);
                    String riskMessage = MapUtils.getString(rs, Constants.riskMessage, "");

                    //按scene分 往data中push最高分数的风险信息 
                    Map<String, Object> currentSceneMap = fact.finalResultGroupByScene.get(scene);
                    if (null == currentSceneMap) {
                        currentSceneMap = new HashMap<String, Object>();
                        currentSceneMap.put(Constants.riskLevel, riskLevel);
                        currentSceneMap.put(Constants.riskMessage, riskMessage);
                        fact.getFinalResultGroupByScene().put(scene, currentSceneMap);
                    } else {
                        int currentRiskLevel = MapUtils.getInteger(currentSceneMap, Constants.riskLevel, 0);

                        //比较risklevel,最高的存到当前的scene map中
                        if (riskLevel > currentRiskLevel) {
                            currentSceneMap.put(Constants.riskLevel, riskLevel);
                            currentSceneMap.put(Constants.riskMessage, riskMessage);
                        }
                    }
                }
            }
        }
        for (Map<String, Object> rs : fact.finalResultGroupByScene.values()) {
            finalResult = compareAndReturn(finalResult, rs);
        }
        fact.setFinalResult(
                ImmutableMap.of(
                        Constants.riskLevel, finalResult.get(Constants.riskLevel),
                        Constants.riskMessage, finalResult.get(Constants.riskMessage)
                ));
        logger.info(Contexts.getLogPrefix() + "execute async rules finished. finalResult: riskLevel="
                + finalResult.get(Constants.riskLevel) + ", riskMessage=" + finalResult.get(Constants.riskMessage));
        TraceLogger.traceLog("执行异步规则完成. finalResult: riskLevel="
                + finalResult.get(Constants.riskLevel) + ", riskMessage=" + finalResult.get(Constants.riskMessage));
        return fact;
    }

    /**
     * 串行执行
     */
    void executeSerial(RiskFact fact) {

        // matchRules      
        List<Rule> matchedRules = Configs.matchRules(fact, true);
        logger.info(Contexts.getLogPrefix() + "matched rules: " + matchedRules.size());
        TraceLogger.traceLog("匹配到 " + matchedRules.size() + " 条规则 ...");
        StatelessRuleEngine statelessRuleEngine = SpringContextHolder.getBean(StatelessRuleEngine.class);

        StopWatch clock = new StopWatch();
        for (Rule rule : matchedRules) {
            String packageName = rule.getRuleNo();
            try {
                clock.reset();
                clock.start();

                // set default result
                Map<String, Object> defaultResult = Maps.newHashMap();
                defaultResult.put(Constants.riskLevel, 0);
                defaultResult.put(Constants.riskMessage, "PASS");
                fact.results.put(rule.getRuleNo(), defaultResult);

                // add current execute ruleNo and logPrefix before execution
                fact.ext.put(Constants.key_ruleNo, rule.getRuleNo());
                fact.ext.put(Constants.key_logPrefix, SarsMonitorContext.getLogPrefix());
                fact.ext.put(Constants.key_traceLoggerParentTransId, TraceLogger.getTransId());

                statelessRuleEngine.execute(packageName, fact);

                // remove current execute ruleNo when finished execution.
                fact.ext.remove(Constants.key_ruleNo);
                fact.ext.remove(Constants.key_logPrefix);
                fact.ext.remove(Constants.key_traceLoggerParentTransId);

                clock.stop();
                long handlingTime = clock.getTime();

                Map<String, Object> result = fact.results.get(packageName);
                result.put(Constants.async, true);
                result.put(Constants.timeUsage, handlingTime);
                logger.info(Contexts.getLogPrefix() + "rule: " + packageName + ", riskLevel: " + result.get(Constants.riskLevel)
                        + ", riskMessage: " + result.get(Constants.riskMessage) + ", usage: " + result.get(Constants.timeUsage) + "ms");

            } catch (Throwable ex) {
                logger.warn(Contexts.getLogPrefix() + "invoke stateless rule failed. packageName: " + packageName, ex);
            }
        }
    }

    /**
     * 并行执行
     */
    void executeParallel(RiskFact fact) {

        // matchRules        
        List<Rule> matchedRules = Configs.matchRules(fact, false);
        logger.info(Contexts.getLogPrefix() + "matched rules: " + matchedRules.size());
        TraceLogger.traceLog("匹配到 " + matchedRules.size() + " 条规则 ...");
        List<Callable<RuleExecuteResultWithEvent>> runs = Lists.newArrayList();
        for (Rule rule : matchedRules) {
            final RiskFact factCopy = BeanMapper.copy(fact, RiskFact.class);

            // set default result
            Map<String, Object> defaultResult = Maps.newHashMap();
            defaultResult.put(Constants.riskLevel, 0);
            defaultResult.put(Constants.riskMessage, "PASS");
            factCopy.results.put(rule.getRuleNo(), defaultResult);

            final StatelessRuleEngine statelessRuleEngine = SpringContextHolder.getBean(StatelessRuleEngine.class);
            final String packageName = rule.getRuleNo();
            final String logPrefix = Contexts.getLogPrefix();

            try {
                //add current execute ruleNo before execution
                factCopy.ext.put(Constants.key_ruleNo, rule.getRuleNo());
                factCopy.ext.put(Constants.key_logPrefix, SarsMonitorContext.getLogPrefix());
                factCopy.ext.put(Constants.key_traceLoggerParentTransId, TraceLogger.getTransId());

                runs.add(new Callable<RuleExecuteResultWithEvent>() {

                    @Override
                    public RuleExecuteResultWithEvent call() throws Exception {
                        try {
                            long start = System.currentTimeMillis();

                            // remove current execute ruleNo when finished execution.
                            statelessRuleEngine.execute(packageName, factCopy);
                            factCopy.ext.remove(Constants.key_ruleNo);
                            factCopy.ext.remove(Constants.key_logPrefix);
                            factCopy.ext.remove(Constants.key_traceLoggerParentTransId);
                            Map<String, Object> result = factCopy.results.get(packageName);
                            result.put(Constants.async, false);
                            result.put(Constants.timeUsage, System.currentTimeMillis() - start);
                            logger.info(logPrefix + "rule: " + packageName + ", riskLevel: " + result.get(Constants.riskLevel)
                                    + ", riskMessage: " + result.get(Constants.riskMessage) + ", usage: " + result.get(Constants.timeUsage) + "ms");
                            return new RuleExecuteResultWithEvent(packageName, factCopy.results, factCopy.finalResultGroupByScene, factCopy.eventBody);
                        } catch (Exception e) {
                            logger.warn(logPrefix + "invoke stateless rule failed. packageName: " + packageName, e);
                        }
                        return null;
                    }

                });

            } catch (Throwable ex) {
                logger.warn(logPrefix + "invoke stateless rule failed. packageName: " + packageName, ex);
            }

        }
        List<RuleExecuteResultWithEvent> rawResult = new ArrayList<RuleExecuteResultWithEvent>();
        try {
            List<Future<RuleExecuteResultWithEvent>> result = excutor.invokeAll(runs, 2L, TimeUnit.SECONDS);
            for (Future f : result) {
                try {
                    if (f.isDone()) {
                        RuleExecuteResultWithEvent r = (RuleExecuteResultWithEvent) f.get();
                        rawResult.add(r);
                    } else {
                        f.cancel(true);
                    }
                } catch (Exception e) {

                }
            }
        } catch (Exception e) {

        }
        if (rawResult.size() > 0) {
            for (RuleExecuteResultWithEvent item : rawResult) {
                // merge eventBody
                if (item.getEventBody() != null) {
                    for (String key : item.getEventBody().keySet()) {
                        if (!fact.eventBody.containsKey(key)) {
                            fact.eventBody.put(key, item.getEventBody().get(key));
                        }
                    }
                }
                // merge results
                if (item.getResults() != null) {
                    fact.results.putAll(item.getResults());
                }
                // merge finalResultGroupByScene
                if (item.getFinalResultGroupByScene() != null) {
                    for (String r : item.getFinalResultGroupByScene().keySet()) {
                        Map<String, Object> rs = item.getFinalResultGroupByScene().get(r);
                        if (rs != null) {
                            Map<String, Object> rsInFact = fact.finalResultGroupByScene.get(r);
                            if (rsInFact != null) {
                                int riskLevel = MapUtils.getIntValue(rs, Constants.riskLevel, 0);
                                int riskLevelInFact = MapUtils.getIntValue(rsInFact, Constants.riskLevel, 0);
                                if (riskLevel > riskLevelInFact) {
                                    fact.finalResultGroupByScene.put(r, rs);
                                }
                            } else {
                                fact.finalResultGroupByScene.put(r, rs);
                            }
                        }
                    }
                }
            }
        }
    }

    class RuleExecuteResultWithEvent {

        private String ruleNo;
        private Map<String, Map<String, Object>> results;
        private Map<String, Map<String, Object>> finalResultGroupByScene;
        private Map<String, Object> eventBody;

        public RuleExecuteResultWithEvent(String ruleNo, Map<String, Map<String, Object>> results, Map<String, Map<String, Object>> finalResultGroupByScene, Map<String, Object> eventBody) {
            this.ruleNo = ruleNo;
            this.results = results;
            this.finalResultGroupByScene = finalResultGroupByScene;
            this.eventBody = eventBody;
        }

        public String getRuleNo() {
            return ruleNo;
        }

        public void setRuleNo(String ruleNo) {
            this.ruleNo = ruleNo;
        }

        public Map<String, Map<String, Object>> getResults() {
            return results;
        }

        public void setResults(Map<String, Map<String, Object>> results) {
            this.results = results;
        }

        public Map<String, Map<String, Object>> getFinalResultGroupByScene() {
            return finalResultGroupByScene;
        }

        public void setFinalResultGroupByScene(Map<String, Map<String, Object>> finalResultGroupByScene) {
            this.finalResultGroupByScene = finalResultGroupByScene;
        }

        public Map<String, Object> getEventBody() {
            return eventBody;
        }

        public void setEventBody(Map<String, Object> eventBody) {
            this.eventBody = eventBody;
        }

    }

    /**
     * 返回分值高的结果作为finalResult
     */
    Map<String, Object> compareAndReturn(Map<String, Object> oldResult, Map<String, Object> newResult) {
        if (newResult == null) {
            return oldResult;
        }
        if (oldResult == null) {
            return newResult;
        }
        int newRriskLevel = MapUtils.getInteger(newResult, Constants.riskLevel, 0);
        int oldRriskLevel = MapUtils.getInteger(oldResult, Constants.riskLevel, 0);
        if (newRriskLevel > oldRriskLevel) {
            return newResult;
        }
        return oldResult;
    }
}
