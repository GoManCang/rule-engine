/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.util;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.counter.model.CounterRuleExecuteResult;
import com.ctrip.infosec.counter.model.PolicyExecuteResult;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

/**
 *
 * @author zhengby
 */
public class Emitter {

    public static void emit(RiskFact fact, int riskLevel, String riskMessage) {
        String ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        emit(fact, ruleNo, riskLevel, riskMessage);
    }

    public static void emit(RiskFact fact, String riskLevelTxt, String riskMessage) {
        if (!StringUtils.isNumeric(riskLevelTxt)) {
            throw new IllegalArgumentException("\"riskLevel\"必须为数字");
        }
        int riskLevel = NumberUtils.toInt(riskLevelTxt);
        emit(fact, riskLevel, riskMessage);
    }

    public static void emit(RiskFact fact, int riskLevel, String riskMessage, String... riskScenes) {
        String ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        emit(fact, ruleNo, riskLevel, riskMessage, riskScenes);
    }

    public static void emit(RiskFact fact, String riskLevelTxt, String riskMessage, String... riskScenes) {
        if (!StringUtils.isNumeric(riskLevelTxt)) {
            throw new IllegalArgumentException("\"riskLevel\"必须为数字");
        }
        int riskLevel = NumberUtils.toInt(riskLevelTxt, 0);
        emit(fact, riskLevel, riskMessage, riskScenes);
    }

    public static void emit(RiskFact fact, String ruleNo, int riskLevel, String riskMessage) {
        if (!Strings.isNullOrEmpty(ruleNo)) {
            Map<String, Object> result = Maps.newHashMap();
            result.put(Constants.riskLevel, riskLevel);
            result.put(Constants.riskMessage, riskMessage);
            fact.results.put(ruleNo, result);
        }
    }

    public static void emit(RiskFact fact, String ruleNo, int riskLevel, String riskMessage, String... riskScenes) {
        if (!Strings.isNullOrEmpty(ruleNo)) {
            Map<String, Object> result = Maps.newHashMap();
            result.put(Constants.riskLevel, riskLevel);
            result.put(Constants.riskMessage, riskMessage);
            result.put(Constants.riskScene, Lists.newArrayList(riskScenes));
            fact.resultsGroupByScene.put(ruleNo, result);
        }
    }

    /**
     * 合并Counter策略执行结果
     */
    public static void emit(RiskFact fact, PolicyExecuteResult counterPolicyExecuteResult) {
        if (counterPolicyExecuteResult.getRuleExecuteResults() == null || counterPolicyExecuteResult.getRuleExecuteResults().isEmpty()) {
            String resultCode = counterPolicyExecuteResult.getResultCode();
            String resultMessage = counterPolicyExecuteResult.getResultMessage();
            if (!"000".equals(resultCode)) {
                emit(fact, resultCode, resultMessage);
            }
        } else {
            Boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync);
            for (CounterRuleExecuteResult ruleExecuteResult : counterPolicyExecuteResult.getRuleExecuteResults()) {
                if (StringUtils.isNotBlank(ruleExecuteResult.getRuleNo())
                        && StringUtils.isNumeric(ruleExecuteResult.getResultCode())) {

                    String ruleNo = ruleExecuteResult.getRuleNo();
                    int riskLevel = NumberUtils.toInt(ruleExecuteResult.getResultCode(), 0);
                    String riskMessage = ruleExecuteResult.getResultMessage();
                    String scenes = ruleExecuteResult.getScenes();
                    if (riskLevel > 0) {
                        Map<String, Object> result = Maps.newHashMap();
                        result.put(Constants.riskLevel, riskLevel);
                        result.put(Constants.riskMessage, riskMessage);
                        if (_isAsync != null) {
                            result.put(Constants.async, _isAsync);
                        }

                        if (StringUtils.isBlank(scenes)) {
                            fact.results.put(ruleNo, result);
                        } else {
                            List<String> riskScenes = Splitter.on(",").omitEmptyStrings().trimResults().splitToList(scenes);
                            result.put(Constants.riskScene, riskScenes);
                            fact.resultsGroupByScene.put(ruleNo, result);
                        }

                        boolean withScene = Constants.eventPointsWithScene.contains(fact.eventPoint);
                        TraceLogger.traceLog("[trace] withScene = " + withScene + ", scenes = [" + (scenes == null ? "" : scenes) + "]");
                        if (!withScene) {
                            if (StringUtils.isNotBlank(scenes)) {
                                TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + ruleNo + "] 执行结果: [在非适配点指定了场景、忽略此次结果] riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage + ", riskScene = [" + scenes + "]");
                            } else {
                                TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + ruleNo + "] 执行结果: riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage);
                            }
                        } else if (withScene) {
                            if (StringUtils.isBlank(scenes)) {
                                TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + ruleNo + "] 执行结果[适配]: [没有指定场景、忽略此次结果] riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage);
                            } else {
                                TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + ruleNo + "] 执行结果[适配]: riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage + ", riskScene = [" + scenes + "]");
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * 合并CounterServer的规则结果
     */
    @Deprecated
    public static void emit(RiskFact fact, List<CounterRuleExecuteResult> counterExecuteResults) {
        mergeCounterResults(fact, counterExecuteResults);
    }

    @Deprecated
    public static void mergeCounterResults(RiskFact fact, List<CounterRuleExecuteResult> counterExecuteResults) {
//        String _ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        Boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync);
        if (counterExecuteResults != null && !counterExecuteResults.isEmpty()) {

            for (CounterRuleExecuteResult ruleExecuteResult : counterExecuteResults) {
                if (StringUtils.isNotBlank(ruleExecuteResult.getRuleNo())
                        && StringUtils.isNumeric(ruleExecuteResult.getResultCode())) {

                    String ruleNo = ruleExecuteResult.getRuleNo();
                    int riskLevel = NumberUtils.toInt(ruleExecuteResult.getResultCode(), 0);
                    String riskMessage = ruleExecuteResult.getResultMessage();
                    String scenes = ruleExecuteResult.getScenes();
                    if (riskLevel > 0) {
                        Map<String, Object> result = Maps.newHashMap();
                        result.put(Constants.riskLevel, riskLevel);
                        result.put(Constants.riskMessage, riskMessage);
                        if (_isAsync != null) {
                            result.put(Constants.async, _isAsync);
                        }

                        if (StringUtils.isBlank(scenes)) {
                            fact.results.put(ruleNo, result);
                        } else {
                            List<String> riskScenes = Splitter.on(",").omitEmptyStrings().trimResults().splitToList(scenes);
                            result.put(Constants.riskScene, riskScenes);
                            fact.resultsGroupByScene.put(ruleNo, result);
                        }

                        boolean withScene = Constants.eventPointsWithScene.contains(fact.eventPoint);
                        TraceLogger.traceLog("[trace] withScene = " + withScene + ", scenes = [" + (scenes == null ? "" : scenes) + "]");
                        if (!withScene) {
                            if (StringUtils.isNotBlank(scenes)) {
                                TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + ruleNo + "] 执行结果: [在非适配点指定了场景、忽略此次结果] riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage + ", riskScene = [" + scenes + "]");
                            } else {
                                TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + ruleNo + "] 执行结果: riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage);
                            }
                        } else if (withScene) {
                            if (StringUtils.isBlank(scenes)) {
                                TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + ruleNo + "] 执行结果[适配]: [没有指定场景、忽略此次结果] riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage);
                            } else {
                                TraceLogger.traceLog("&gt;&gt;&gt;&gt; [" + ruleNo + "] 执行结果[适配]: riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage + ", riskScene = [" + scenes + "]");
                            }
                        }
                    }
                }
            }
        }
    }
}
