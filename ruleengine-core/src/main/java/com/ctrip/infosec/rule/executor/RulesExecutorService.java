/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import static com.ctrip.infosec.configs.utils.EventBodyUtils.valueAsList;
import static com.ctrip.infosec.configs.utils.EventBodyUtils.valueAsMap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.Rule;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.rulemonitor.RuleMonitorHelper;
import com.ctrip.infosec.configs.rulemonitor.RuleMonitorType;
import com.ctrip.infosec.configs.utils.BeanMapper;
import com.ctrip.infosec.configs.utils.EventBodyUtils;
import static com.ctrip.infosec.configs.utils.EventBodyUtils.valueAsInt;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.engine.StatelessRuleEngine;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.meidusa.fastjson.JSON;

/**
 * 使用线程池并行执行规则
 *
 * @author zhengby
 */
@Service
public class RulesExecutorService {

    private static final Logger logger = LoggerFactory.getLogger(RulesExecutorService.class);
    // 秒
    private int timeout = GlobalConfig.getInteger("Rules.executor.timeout", 2);

    /**
     * 执行同步规则
     */
    public RiskFact executeSyncRules(RiskFact fact) {

        if (fact.results == null) {
            fact.setResults(new HashMap<String, Map<String, Object>>());
        }
        if (fact.ext == null) {
            fact.setExt(new HashMap<String, Object>());
        }
        executeParallel(fact);
        buidFinalResult(fact, false);

        if (!Constants.eventPointsWithScene.contains(fact.eventPoint)) {
            TraceLogger.traceLog("同步规则执行完成. finalResult: " + JSON.toJSONString(fact.finalResult));
        } else {
            TraceLogger.traceLog("同步规则执行完成[适配]. finalResultGroupByScene: " + JSON.toJSONString(fact.finalResultGroupByScene));
        }
        return fact;
    }

    /**
     * 执行异步规则
     */
    public RiskFact executeAsyncRules(RiskFact fact) {

        if (fact.results == null) {
            fact.setResults(new HashMap<String, Map<String, Object>>());
        }
        if (fact.ext == null) {
            fact.setExt(new HashMap<String, Object>());
        }
        executeSerial(fact);
        buidFinalResult(fact, true);

        if (!Constants.eventPointsWithScene.contains(fact.eventPoint)) {
            TraceLogger.traceLog("异步规则执行完成. finalResult: " + JSON.toJSONString(fact.finalResult));
        } else {
            TraceLogger.traceLog("异步规则执行完成[适配]. finalResultGroupByScene: " + JSON.toJSONString(fact.finalResultGroupByScene));
        }
        return fact;
    }

    void buidFinalResult(RiskFact fact, boolean isAsync) {

        // finalResult
        Map<String, Object> finalResult = Constants.defaultResult;
        for (Map<String, Object> rs : fact.results.values()) {
            finalResult = compareAndReturn(finalResult, rs);
        }
        fact.setFinalResult(Maps.newHashMap(finalResult));
        // 黑白名单只在同步起作用
        if (!fact.finalWhitelistResult.isEmpty() && !isAsync) {
            // 0 : 白名单
            // 95：会验证其他规则，但是最终风险为95，不会变成其他风险
            // 97：需要判读最高风险是否超过195（包含），如果超过（包含）则按最高风险处理，其他的话，按97返回低风险
            int whitelistRiskLevel = valueAsInt(fact.finalWhitelistResult, Constants.riskLevel);
            if (whitelistRiskLevel == 0) {
                fact.setFinalResult(Maps.newHashMap(Constants.defaultResult));
            } else if (whitelistRiskLevel == 95) {
                fact.setFinalResult(Maps.newHashMap(fact.finalWhitelistResult));
            } else if (whitelistRiskLevel == 97) {
                int riskLevel = valueAsInt(finalResult, Constants.riskLevel);
                if (riskLevel < 195) {
                    fact.setFinalResult(Maps.newHashMap(fact.finalWhitelistResult));
                }
            }
        }
        fact.finalResult.remove(Constants.timeUsage);

        // finalResultGroupByScene
        Map<String, Map<String, Object>> finalResultGroupByScene = fact.finalResultGroupByScene;
        for (Map<String, Object> rs : fact.resultsGroupByScene.values()) {
            List<String> sceneTypeList = valueAsList(rs, Constants.riskScene);
            if (sceneTypeList != null) {
                for (String sceneType : sceneTypeList) {
                    int riskLevel = MapUtils.getInteger(rs, Constants.riskLevel, 0);
                    String riskMessage = MapUtils.getString(rs, Constants.riskMessage, "");

                    // 按场景往finalResultGroupByScene中put最高分数的结果 
                    Map<String, Object> sceneResult = finalResultGroupByScene.get(sceneType);
                    if (null == sceneResult) {
                        sceneResult = new HashMap<>();
                        sceneResult.put(Constants.riskLevel, riskLevel);
                        sceneResult.put(Constants.riskMessage, riskMessage);
                        finalResultGroupByScene.put(sceneType, sceneResult);
                    } else {
                        int lastRiskLevel = MapUtils.getInteger(sceneResult, Constants.riskLevel, 0);
                        if (riskLevel > lastRiskLevel) {
                            sceneResult.put(Constants.riskLevel, riskLevel);
                            sceneResult.put(Constants.riskMessage, riskMessage);
                        }
                    }
                }
            }
            Map<String, Map<String, Map<String, String>>> subLevelGroupBySceneType = valueAsMap(rs, Constants.subSceneType);
            if (subLevelGroupBySceneType != null) {
                for (String sceneType : subLevelGroupBySceneType.keySet()) {
                    Map<String, Map<String, String>> subLevelGroupBySubSceneType = subLevelGroupBySceneType.get(sceneType);

                    //如果根节点不存在，则创建
                    Map<String, Object> sceneResult = finalResultGroupByScene.get(sceneType);
                    if (null == sceneResult) {
                        sceneResult = new HashMap<>();
                        sceneResult.put(Constants.riskLevel, 0);
                        sceneResult.put(Constants.riskMessage, "PASS");
                        finalResultGroupByScene.put(sceneType, sceneResult);
                    }

                    int sceneRiskLevel = EventBodyUtils.valueAsInt(sceneResult, Constants.riskLevel);
                    Map<String, Map<String, String>> finalSubResults = Maps.newHashMap();

                    for (Entry<String, Map<String, String>> entry : subLevelGroupBySubSceneType.entrySet()) {

                        //只有子场景分数比父场景大，才保留
                        int subSceneRiskLevel = EventBodyUtils.valueAsInt(entry.getValue(), Constants.riskLevel);
                        if (subSceneRiskLevel > sceneRiskLevel) {
                            finalSubResults.put(entry.getKey(), entry.getValue());
                        }

                    }

                    sceneResult.put(Constants.subSceneType, finalSubResults);
                }
            }
        }
        fact.setFinalResultGroupByScene(Maps.newHashMap(finalResultGroupByScene));
        fact.finalResultGroupByScene.remove(Constants.timeUsage);
    }

    /**
     * 串行执行
     */
    void executeSerial(RiskFact fact) {

        // matchRules      
        List<Rule> matchedRules = Configs.matchRules(fact, true);
        TraceLogger.traceLog("匹配到 " + matchedRules.size() + " 条规则 ...");
        StatelessRuleEngine statelessRuleEngine = SpringContextHolder.getBean(StatelessRuleEngine.class);

        StopWatch clock = new StopWatch();
        for (Rule rule : matchedRules) {
            String packageName = rule.getRuleNo();
            RuleMonitorHelper.newTrans(fact, RuleMonitorType.RULE,packageName);
            TraceLogger.beginNestedTrans(fact.eventId);
            TraceLogger.setNestedLogPrefix("[" + packageName + "]");
            Contexts.setPolicyOrRuleNo(packageName);
            try {
                clock.reset();
                clock.start();

                // set default result
                if (!Constants.eventPointsWithScene.contains(fact.eventPoint)) {
                    Map<String, Object> defaultResult = Maps.newHashMap();
                    defaultResult.put(Constants.riskLevel, 0);
                    defaultResult.put(Constants.riskMessage, "PASS");
                    fact.results.put(rule.getRuleNo(), defaultResult);
                }

                // add current execute ruleNo and logPrefix before execution
                fact.ext.put(Constants.key_ruleNo, rule.getRuleNo());
                fact.ext.put(Constants.key_isAsync, true);

                statelessRuleEngine.execute(packageName, fact);

                // remove current execute ruleNo when finished execution.
                fact.ext.remove(Constants.key_ruleNo);
                fact.ext.remove(Constants.key_isAsync);

                clock.stop();
                long handlingTime = clock.getTime();

                if (!Constants.eventPointsWithScene.contains(fact.eventPoint)) {

                    Map<String, Object> resultWithScene = fact.resultsGroupByScene.get(packageName);
                    if (resultWithScene != null) {
                        resultWithScene.put(Constants.async, false);
                        resultWithScene.put(Constants.timeUsage, handlingTime);

                        TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果: [在非适配点指定了场景、忽略此次结果] riskLevel = " + resultWithScene.get(Constants.riskLevel)
                                + ", riskMessage = " + resultWithScene.get(Constants.riskMessage) + ", riskScene = " + resultWithScene.get(Constants.riskScene)
                                + ", usage = " + resultWithScene.get(Constants.timeUsage) + "ms");
                    }

                    Map<String, Object> result = fact.results.get(packageName);
                    if (result != null) {
                        result.put(Constants.async, true);
                        result.put(Constants.timeUsage, handlingTime);

                        TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果: riskLevel = " + result.get(Constants.riskLevel)
                                + ", riskMessage = " + result.get(Constants.riskMessage) + ", usage = " + result.get(Constants.timeUsage) + "ms");
                    }

                } else {

                    Map<String, Object> result = fact.results.get(packageName);
                    if (result != null) {
                        result.put(Constants.async, false);
                        result.put(Constants.timeUsage, handlingTime);
                        int riskLevel = MapUtils.getIntValue(result, Constants.riskLevel, 0);
                        if (riskLevel > 0) {
                            TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果: [没有指定场景、忽略此次结果] riskLevel = " + result.get(Constants.riskLevel)
                                    + ", riskMessage = " + result.get(Constants.riskMessage) + ", usage = " + result.get(Constants.timeUsage) + "ms");
                        }
                    }

                    Map<String, Object> resultWithScene = fact.resultsGroupByScene.get(packageName);
                    if (resultWithScene != null) {
                        resultWithScene.put(Constants.async, true);
                        resultWithScene.put(Constants.timeUsage, handlingTime);

                        TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果[适配]: riskLevel = " + resultWithScene.get(Constants.riskLevel)
                                + ", riskMessage = " + resultWithScene.get(Constants.riskMessage) + ", riskScene = " + resultWithScene.get(Constants.riskScene)
                                + ", usage = " + resultWithScene.get(Constants.timeUsage) + "ms");
                    } else {
                        TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果[适配]: 没有命中适配规则");
                    }
                }

            } catch (Throwable ex) {
                logger.warn(Contexts.getLogPrefix() + "执行规则异常. packageName: " + packageName, ex);
                TraceLogger.traceLog("[" + rule.getRuleNo() + "] EXCEPTION: " + ex.toString());
            } finally {
                TraceLogger.commitNestedTrans();
                RuleMonitorHelper.commitTrans(fact);
                Contexts.clearLogPrefix();
            }
        }
    }

    /**
     * 并行执行
     */
    void executeParallel(RiskFact fact) {

        // matchRules        
        List<Rule> matchedRules = Configs.matchRules(fact, false);

        TraceLogger.traceLog("匹配到 " + matchedRules.size() + " 条规则 ...");
        List<Callable<RuleExecuteResultWithEvent>> runs = Lists.newArrayList();
        for (Rule rule : matchedRules) {
            final RiskFact factCopy = BeanMapper.copy(fact, RiskFact.class);

            // set default result
            if (!Constants.eventPointsWithScene.contains(factCopy.eventPoint)) {
                Map<String, Object> defaultResult = Maps.newHashMap();
                defaultResult.put(Constants.riskLevel, 0);
                defaultResult.put(Constants.riskMessage, "PASS");
                factCopy.results.put(rule.getRuleNo(), defaultResult);
            }

            final StatelessRuleEngine statelessRuleEngine = SpringContextHolder.getBean(StatelessRuleEngine.class);
            final String packageName = rule.getRuleNo();
            final String _logPrefix = Contexts.getLogPrefix();
            final String _traceLoggerParentTransId = TraceLogger.getTransId();

            try {
                // add current execute ruleNo before execution
                factCopy.ext.put(Constants.key_ruleNo, rule.getRuleNo());
                factCopy.ext.put(Constants.key_isAsync, false);

                runs.add(new Callable<RuleExecuteResultWithEvent>() {

                    @Override
                    public RuleExecuteResultWithEvent call() throws Exception {
                    	RuleMonitorHelper.newTrans(factCopy, RuleMonitorType.RULE,packageName);
                        TraceLogger.beginTrans(factCopy.eventId);
                        TraceLogger.setParentTransId(_traceLoggerParentTransId);
                        TraceLogger.setLogPrefix("[" + packageName + "]");
                        Contexts.setPolicyOrRuleNo(packageName);
                        try {
                            long start = System.currentTimeMillis();
                            // remove current execute ruleNo when finished execution.
                            statelessRuleEngine.execute(packageName, factCopy);

                            long handlingTime = System.currentTimeMillis() - start;

                            if (!Constants.eventPointsWithScene.contains(factCopy.eventPoint)) {

                                Map<String, Object> resultWithScene = factCopy.resultsGroupByScene.get(packageName);
                                if (resultWithScene != null) {
                                    resultWithScene.put(Constants.async, false);
                                    resultWithScene.put(Constants.timeUsage, handlingTime);

                                    TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果: [在非适配点指定了场景、忽略此次结果] riskLevel = " + resultWithScene.get(Constants.riskLevel)
                                            + ", riskMessage = " + resultWithScene.get(Constants.riskMessage) + ", riskScene = " + resultWithScene.get(Constants.riskScene)
                                            + ", usage = " + resultWithScene.get(Constants.timeUsage) + "ms");
                                }

                                Map<String, Object> result = factCopy.results.get(packageName);
                                if (result != null) {
                                    result.put(Constants.async, false);
                                    result.put(Constants.timeUsage, handlingTime);

                                    TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果: riskLevel = " + result.get(Constants.riskLevel)
                                            + ", riskMessage = " + result.get(Constants.riskMessage) + ", usage = " + result.get(Constants.timeUsage) + "ms");
                                }

                            } else {

                                Map<String, Object> result = factCopy.results.get(packageName);
                                if (result != null) {
                                    result.put(Constants.async, false);
                                    result.put(Constants.timeUsage, handlingTime);
                                    int riskLevel = MapUtils.getIntValue(result, Constants.riskLevel, 0);
                                    if (riskLevel > 0) {
                                        TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果[适配]: [适配接入点必须指定场景、忽略此次结果] riskLevel = " + result.get(Constants.riskLevel)
                                                + ", riskMessage = " + result.get(Constants.riskMessage) + ", usage = " + result.get(Constants.timeUsage) + "ms");
                                    }
                                }

                                Map<String, Object> resultWithScene = factCopy.resultsGroupByScene.get(packageName);
                                if (resultWithScene != null) {
                                    resultWithScene.put(Constants.async, false);
                                    resultWithScene.put(Constants.timeUsage, handlingTime);

                                    TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果[适配]: riskLevel = " + resultWithScene.get(Constants.riskLevel)
                                            + ", riskMessage = " + resultWithScene.get(Constants.riskMessage) + ", riskScene = " + resultWithScene.get(Constants.riskScene)
                                            + ", usage = " + resultWithScene.get(Constants.timeUsage) + "ms");
                                } else {
                                    TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + packageName + "] 执行结果[适配]: 没有命中适配规则");
                                }
                            }
                            return new RuleExecuteResultWithEvent(packageName, factCopy.results, factCopy.resultsGroupByScene, factCopy.eventBody, factCopy.ext);
                        } catch (Exception e) {
                            logger.warn(_logPrefix + "执行规则异常. packageName: " + packageName, e);
                        } finally {
                            TraceLogger.commitTrans();
                            RuleMonitorHelper.commitTrans2Trunk(factCopy);
                            Contexts.clearLogPrefix();
                        }
                        return null;
                    }

                });

            } catch (Throwable ex) {
                logger.warn(_logPrefix + "执行规则异常. packageName: " + packageName, ex);
            }

        }
        List<RuleExecuteResultWithEvent> rawResult = new ArrayList<RuleExecuteResultWithEvent>();
        try {
            List<Future<RuleExecuteResultWithEvent>> result = ParallelExecutorHolder.excutor.invokeAll(runs, timeout, TimeUnit.SECONDS);
            for (Future f : result) {
                try {
                    if (f.isDone()) {
                        RuleExecuteResultWithEvent r = (RuleExecuteResultWithEvent) f.get();
                        rawResult.add(r);
                    } else {
                        f.cancel(true);
                    }
                } catch (Exception e) {
                    // ignored
                }
            }
        } catch (Exception e) {
            // ignored
        }
        if (rawResult.size() > 0) {
            for (RuleExecuteResultWithEvent item : rawResult) {
                // merge eventBody
                if (item.getEventBody() != null) {
                    for (String key : item.getEventBody().keySet()) {
                        Object value = item.getEventBody().get(key);
                        if (!fact.eventBody.containsKey(key) && value != null) {
                            fact.eventBody.put(key, value);
                        }
                    }
                }
                // merge ext
                if (item.getExt() != null) {
                    for (String key : item.getExt().keySet()) {
                        Object value = item.getExt().get(key);
                        if (!fact.ext.containsKey(key) && value != null) {
                            fact.ext.put(key, value);
                        }
                    }
                }
                // merge results
                if (item.getResults() != null) {
                    fact.results.putAll(item.getResults());
                }
                // merge resultsGroupByScene
                if (item.getResultsGroupByScene() != null) {
                    fact.resultsGroupByScene.putAll(item.getResultsGroupByScene());
                }
            }
        }
    }

    class RuleExecuteResultWithEvent {

        private String ruleNo;
        private Map<String, Map<String, Object>> results;
        private Map<String, Map<String, Object>> resultsGroupByScene;
        private Map<String, Object> eventBody;
        private Map<String, Object> ext;

        public RuleExecuteResultWithEvent(String ruleNo, Map<String, Map<String, Object>> results, Map<String, Map<String, Object>> resultsGroupByScene, Map<String, Object> eventBody, Map<String, Object> ext) {
            this.ruleNo = ruleNo;
            this.results = results;
            this.resultsGroupByScene = resultsGroupByScene;
            this.eventBody = eventBody;
            this.ext = ext;
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

        public Map<String, Map<String, Object>> getResultsGroupByScene() {
            return resultsGroupByScene;
        }

        public void setResultsGroupByScene(Map<String, Map<String, Object>> resultsGroupByScene) {
            this.resultsGroupByScene = resultsGroupByScene;
        }

        public Map<String, Object> getEventBody() {
            return eventBody;
        }

        public void setEventBody(Map<String, Object> eventBody) {
            this.eventBody = eventBody;
        }

        public Map<String, Object> getExt() {
            return ext;
        }

        public void setExt(Map<String, Object> ext) {
            this.ext = ext;
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
