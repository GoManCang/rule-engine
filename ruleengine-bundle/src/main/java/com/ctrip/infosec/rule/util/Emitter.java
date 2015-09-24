/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.util;

import static com.ctrip.infosec.configs.utils.EventBodyUtils.valueAsInt;
import static com.ctrip.infosec.configs.utils.EventBodyUtils.valueAsString;

import java.util.List;
import java.util.Map;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.rulemonitor.RuleMonitorHelper;
import com.ctrip.infosec.configs.utils.EventBodyUtils;
import com.ctrip.infosec.counter.model.CounterRuleExecuteResult;
import com.ctrip.infosec.counter.model.PolicyExecuteResult;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

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

    public static void emit(RiskFact fact, int riskLevel, String riskMessage, String... riskScene) {
        String ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        emit(fact, ruleNo, riskLevel, riskMessage, riskScene);
    }

    public static void emit(RiskFact fact, String riskLevelTxt, String riskMessage, String... riskScene) {
        if (!StringUtils.isNumeric(riskLevelTxt)) {
            throw new IllegalArgumentException("\"riskLevel\"必须为数字");
        }
        int riskLevel = NumberUtils.toInt(riskLevelTxt, 0);
        emit(fact, riskLevel, riskMessage, riskScene);
    }

    public static void emit(RiskFact fact, String ruleNo, int riskLevel, String riskMessage) {
        boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
        if (!Strings.isNullOrEmpty(ruleNo)) {
            Map<String, Object> result = Maps.newHashMap();
            result.put(Constants.riskLevel, riskLevel);
            result.put(Constants.riskMessage, riskMessage);
            result.put(Constants.async, _isAsync);
            if (!_isAsync) {
                result.put(Constants.ruleType, "N");
                fact.results.put(ruleNo, result);
            } else {
                result.put(Constants.ruleType, "NA");
                fact.results4Async.put(ruleNo, result);
            }

            RuleMonitorHelper.addRiskRuleNo(ruleNo);
        }

    }

    public static void emit(RiskFact fact, String ruleNo, int riskLevel, String riskMessage, String... riskScene) {
        boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
        if (!Strings.isNullOrEmpty(ruleNo)) {
            Map<String, Object> result = Maps.newHashMap();
            result.put(Constants.riskLevel, riskLevel);
            result.put(Constants.riskMessage, riskMessage);
            result.put(Constants.riskScene, Lists.newArrayList(riskScene));
            result.put(Constants.async, _isAsync);
            if (!_isAsync) {
                result.put(Constants.ruleType, "S");
                fact.resultsGroupByScene.put(ruleNo, result);
            } else {
                result.put(Constants.ruleType, "SA");
                fact.resultsGroupByScene4Async.put(ruleNo, result);
            }

            RuleMonitorHelper.addRiskRuleNo(ruleNo);
        }
    }

//
//    适配支持subSceneType:
//    
//    resultsGroupByScene：
//    {
//        "R1": {
//            "riskLevel": 278,
//            "riskMessage": "交易有风险",
//            "riskScene": [
//                "PAYMENT-CONF-CC",
//                "PAYMENT-CONF-DCARD"
//            ],
//            "subSceneType": {
//                "PAYMENT-CONF-CC": {
//                    "CC_ABC": {
//                        "riskLevel": 295,
//                        "riskMessage": "交易有风险"
//                    },
//                    "CC_BOC": {
//                        "riskLevel": 295,
//                        "riskMessage": "交易有风险"
//                    }
//                }
//            }
//        }
//    }
//    
//    finalResultGroupByScene：
//    {
//        "PAYMENT-CONF-CC": {
//            "riskLevel": 278,
//            "riskMessage": "交易有风险",
//            "subSceneType": {
//                "CC_ABC": {
//                    "riskLevel": 295,
//                    "riskMessage": "交易有风险"
//                },
//                "CC_BOC": {
//                    "riskLevel": 295,
//                    "riskMessage": "交易有风险"
//                }
//            }
//        },
//        "PAYMENT-CONF-DCARD": {
//            "riskLevel": 278,
//            "riskMessage": "交易有风险"
//        }
//    }
    public static void emit(RiskFact fact, int riskLevel, String riskMessage, String[] riskScene, Map<String, Map<String, Map<String, String>>> subSceneType) {
        String ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        emit(fact, ruleNo, riskLevel, riskMessage, riskScene, subSceneType);
    }

    public static void emit(RiskFact fact, String ruleNo, int riskLevel, String riskMessage, String[] riskScene, Map<String, Map<String, Map<String, String>>> subSceneType) {
        boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
        if (!Strings.isNullOrEmpty(ruleNo)) {
            Map<String, Object> result = Maps.newHashMap();
            result.put(Constants.riskLevel, riskLevel);
            result.put(Constants.riskMessage, riskMessage);
            result.put(Constants.riskScene, Lists.newArrayList(riskScene));
            result.put(Constants.subSceneType, subSceneType);
            result.put(Constants.async, _isAsync);
            if (!_isAsync) {
                result.put(Constants.ruleType, "S");
                fact.resultsGroupByScene.put(ruleNo, result);
            } else {
                result.put(Constants.ruleType, "SA");
                fact.resultsGroupByScene4Async.put(ruleNo, result);
            }
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
            boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
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
                        result.put(Constants.async, _isAsync);

                        if (StringUtils.isBlank(scenes)) {
                            if (!_isAsync) {
                                result.put(Constants.ruleType, "N");
                                fact.results.put(ruleNo, result);
                            } else {
                                result.put(Constants.ruleType, "NA");
                                fact.results4Async.put(ruleNo, result);
                            }
                        } else {
                            List<String> riskScenes = Splitter.on(",").omitEmptyStrings().trimResults().splitToList(scenes);
                            result.put(Constants.riskScene, riskScenes);
                            if (!_isAsync) {
                                result.put(Constants.ruleType, "S");
                                fact.resultsGroupByScene.put(ruleNo, result);
                            } else {
                                result.put(Constants.ruleType, "SA");
                                fact.resultsGroupByScene4Async.put(ruleNo, result);
                            }
                        }

                        boolean withScene = Constants.eventPointsWithScene.contains(fact.eventPoint);
                        TraceLogger.traceLog("[trace] withScene = " + withScene + ", scenes = [" + (scenes == null ? "" : scenes) + "]");
                        if (!withScene) {
                            if (StringUtils.isNotBlank(scenes)) {
                                TraceLogger.traceLog(">>>> [" + ruleNo + "] 执行结果: [在非适配点指定了场景、忽略此次结果] riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage + ", riskScene = [" + scenes + "]");
                            } else {
                                TraceLogger.traceLog(">>>> [" + ruleNo + "] 执行结果: riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage);
                            }
                        } else if (withScene) {
                            if (StringUtils.isBlank(scenes)) {
                                TraceLogger.traceLog(">>>> [" + ruleNo + "] 执行结果[适配]: [没有指定场景、忽略此次结果] riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage);
                            } else {
                                TraceLogger.traceLog(">>>> [" + ruleNo + "] 执行结果[适配]: riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage + ", riskScene = [" + scenes + "]");
                            }
                        }
                    }
                }
            }
        }
    }

    @Deprecated
    public static void emit(RiskFact fact, List<CounterRuleExecuteResult> counterExecuteResults) {
        mergeCounterResults(fact, counterExecuteResults);
    }

    @Deprecated
    public static void mergeCounterResults(RiskFact fact, List<CounterRuleExecuteResult> counterExecuteResults) {
//        String _ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
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
                        result.put(Constants.async, _isAsync);

                        if (StringUtils.isBlank(scenes)) {
                            if (!_isAsync) {
                                result.put(Constants.ruleType, "N");
                                fact.results.put(ruleNo, result);
                            } else {
                                result.put(Constants.ruleType, "NA");
                                fact.results4Async.put(ruleNo, result);
                            }
                        } else {
                            List<String> riskScenes = Splitter.on(",").omitEmptyStrings().trimResults().splitToList(scenes);
                            result.put(Constants.riskScene, riskScenes);
                            if (!_isAsync) {
                                result.put(Constants.ruleType, "S");
                                fact.resultsGroupByScene.put(ruleNo, result);
                            } else {
                                result.put(Constants.ruleType, "SA");
                                fact.resultsGroupByScene4Async.put(ruleNo, result);
                            }
                        }

                        boolean withScene = Constants.eventPointsWithScene.contains(fact.eventPoint);
                        TraceLogger.traceLog("[trace] withScene = " + withScene + ", scenes = [" + (scenes == null ? "" : scenes) + "]");
                        if (!withScene) {
                            if (StringUtils.isNotBlank(scenes)) {
                                TraceLogger.traceLog(">>>> [" + ruleNo + "] 执行结果: [在非适配点指定了场景、忽略此次结果] riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage + ", riskScene = [" + scenes + "]");
                            } else {
                                TraceLogger.traceLog(">>>> [" + ruleNo + "] 执行结果: riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage);
                            }
                        } else if (withScene) {
                            if (StringUtils.isBlank(scenes)) {
                                TraceLogger.traceLog(">>>> [" + ruleNo + "] 执行结果[适配]: [没有指定场景、忽略此次结果] riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage);
                            } else {
                                TraceLogger.traceLog(">>>> [" + ruleNo + "] 执行结果[适配]: riskLevel = " + riskLevel
                                        + ", riskMessage = " + riskMessage + ", riskScene = [" + scenes + "]");
                            }
                        }
                    }
                }
            }
        }
    }

    // 黑白名单库类型
    private static final String BWList_ACCOUNT = "ACCOUNT";
    private static final String BWlist_BW = "BW";

    /**
     * 合并黑白名单规则引擎结果
     */
    public static void emitBWListResults(RiskFact fact, List<Map<String, String>> bwlistResults) {
        boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
        if (_isAsync || bwlistResults == null || bwlistResults.isEmpty()) {
            return;
        }
        // 白名单结果(只看BW的)
        for (Map<String, String> resultMap : bwlistResults) {
            String ruleType = valueAsString(resultMap, "ruleType");
            String ruleNo = valueAsString(resultMap, "ruleName");
            String riskMessage = "白名单: " + valueAsString(resultMap, "ruleRemark"); // "命中白名单规则: [" + Joiner.on(", ").withKeyValueSeparator(":").useForNull("").join(resultMap) + "]";
            int riskLevel = valueAsInt(resultMap, "riskLevel");

            if (ruleType.equals(BWlist_BW)) {
                if (riskLevel == 0) {
                    fact.finalWhitelistResult.put(Constants.riskLevel, 0);
                    fact.finalWhitelistResult.put(Constants.riskMessage, riskMessage);
                    emit(fact, riskLevel, riskMessage);
                    break;
                }
                if (riskLevel == 95) {
                    fact.finalWhitelistResult.put(Constants.riskLevel, 95);
                    fact.finalWhitelistResult.put(Constants.riskMessage, riskMessage);
                    emit(fact, riskLevel, riskMessage);
                    break;
                }
                // 97
                if (riskLevel < 100 && riskLevel >= 90) {
                    fact.finalWhitelistResult.put(Constants.riskLevel, 97);
                    fact.finalWhitelistResult.put(Constants.riskMessage, riskMessage);
                    emit(fact, riskLevel, riskMessage);
                }
            }
        }

        // 黑名单结果
        if (fact.finalWhitelistResult.isEmpty()
                || (fact.finalWhitelistResult.containsKey(Constants.riskLevel) && valueAsInt(fact.finalWhitelistResult, Constants.riskLevel) == 97)) {
            emitBListResults(fact, bwlistResults);
        }

        // 最后只是为了在checkResultLog表里存B的规则，再最后遍历一次
        for (Map<String, String> resultMap : bwlistResults) {
            String ruleType = valueAsString(resultMap, "ruleType");
            String ruleName = valueAsString(resultMap, "ruleName");
            String riskMessage = valueAsString(resultMap, "ruleRemark");
            String ruleId = valueAsString(resultMap, "ruleID");
            int riskLevel = valueAsInt(resultMap, "riskLevel");

            if (ruleType.equals(BWlist_BW) && riskLevel > 0) {
                Map<String, Object> result = Maps.newHashMap();
                result.put(Constants.riskLevel, riskLevel);
                result.put(Constants.riskMessage, riskMessage);
                result.put(Constants.ruleType, "B");
                result.put(Constants.ruleId, ruleId);
                result.put(Constants.ruleName, ruleName);
                fact.whitelistResults.put(ruleId, result);
            }
        }
    }

    /**
     * 合并黑名单规则引擎结果
     */
    public static void emitBListResults(RiskFact fact, List<Map<String, String>> bwlistResults) {

        //result: [{"ruleType":"ACCOUNT","ruleID":0,"ruleName":"CREDIT-EXCHANGE","riskLevel":295,"ruleRemark":""},
        //         {"ruleType":"ACCOUNT","ruleID":0,"ruleName":"CREDIT-EXCHANGE1","riskLevel":80,"ruleRemark":""}]
        boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
        if (_isAsync) {
            return;
        }

        String orderType = EventBodyUtils.valueAsString(fact.getEventBody(), "orderType");
        boolean isAdapterFact = Constants.eventPointsWithScene.contains(fact.eventPoint);
        boolean isScoreFact = orderType.equals("12"); //邮轮

        if (isAdapterFact) {
            //适配点
            for (Map<String, String> resultMap : bwlistResults) {

                String ruleType = valueAsString(resultMap, "ruleType");
                String ruleNo = valueAsString(resultMap, "ruleName");
                String riskMessage = "黑名单: " + valueAsString(resultMap, "ruleRemark"); // "命中黑名单规则: [" + Joiner.on(", ").withKeyValueSeparator(":").useForNull("").join(resultMap) + "]";
                int riskLevel = valueAsInt(resultMap, "riskLevel");

                if (ruleType.equals(BWList_ACCOUNT)) {
                    emit(fact, ruleNo, riskLevel, riskMessage, ruleNo);
                } else if (ruleType.equals(BWlist_BW) && riskLevel > 100) {
                    emit(fact, "PAYMENT-CONF-LIPIN", 295, riskMessage, "PAYMENT-CONF-LIPIN");
                }

            }

        } else {

            String finalRuleNo = null;
            int finalRiskLevel = 0;
            String finalRiskMessage = null;

            for (Map<String, String> resultMap : bwlistResults) {

                String ruleType = valueAsString(resultMap, "ruleType");
                String ruleNo = valueAsString(resultMap, "ruleName");
                String riskMessage = "黑名单: " + valueAsString(resultMap, "ruleRemark");
                int riskLevel = valueAsInt(resultMap, "riskLevel");

                if (isScoreFact) {
                    //积分点,不区分ruleType
                    if (riskLevel > finalRiskLevel) {
                        finalRuleNo = ruleNo;
                        finalRiskLevel = riskLevel;
                        finalRiskMessage = riskMessage; // "命中黑名单规则: [" + Joiner.on(", ").withKeyValueSeparator(":").useForNull("").join(resultMap) + "]";
                    }

                } else {
                    //其他授权，下单点
                    //只需要ruleType = BW
                    if (ruleType.equals(BWlist_BW)) {
                        if (riskLevel > finalRiskLevel) {
                            finalRuleNo = ruleNo;
                            finalRiskLevel = riskLevel;
                            finalRiskMessage = riskMessage; // "命中黑名单规则: [" + Joiner.on(", ").withKeyValueSeparator(":").useForNull("").join(resultMap) + "]";
                        }
                    }
                }
            }

            // 97：需要判读最高风险是否超过195（包含），如果超过（包含）则按最高风险处理，其他的话，按97返回低风险
            int whitelistRiskLevel = valueAsInt(fact.finalWhitelistResult, Constants.riskLevel);
            if (whitelistRiskLevel == 97 && finalRiskLevel < 195) {
                emit(fact, 97, finalRiskMessage);
            } else {
                emit(fact, finalRiskLevel, finalRiskMessage);
            }
        }
    }

    /**
     * Counter里的名单库
     */
//    public static void emitBWListResult(RiskFact fact, int riskLevel, String riskMessage) {
//        String ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
//        boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
//        if (!_isAsync && !Strings.isNullOrEmpty(ruleNo)) {
//            if (riskLevel == 0) {
//                fact.finalWhitelistResult.put(Constants.riskLevel, riskLevel);
//                fact.finalWhitelistResult.put(Constants.riskMessage, riskMessage);
//                emit(fact, riskLevel, riskMessage);
//            } else if (riskLevel >= 200) {
//                fact.finalWhitelistResult.put(Constants.riskLevel, riskLevel);
//                fact.finalWhitelistResult.put(Constants.riskMessage, riskMessage);
//                emit(fact, riskLevel, riskMessage);
//            }
//        }
//    }

    /**
     * 提交升降分值的结果
     */
    public static void emitLeveldownResult(RiskFact fact, int riskLevel, String riskMessage) {
        String ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync, false);
        if (!_isAsync && !Strings.isNullOrEmpty(ruleNo)) {
            Map<String, Object> result = Maps.newHashMap();
            result.put(Constants.riskLevel, riskLevel);
            result.put(Constants.riskMessage, riskMessage);
            result.put(Constants.async, _isAsync);
            result.put(Constants.ruleType, "N");
            fact.leveldownResults.put(ruleNo, result);
            buidFinalResultAfterEmitLeveldownResult(fact, _isAsync);
            RuleMonitorHelper.addRiskRuleNo(ruleNo);
        }
    }

    /**
     * 在emitLeveldownResult后重新计算finalResult
     */
    static void buidFinalResultAfterEmitLeveldownResult(RiskFact fact, boolean _isAsync) {
        if (!_isAsync && fact.leveldownResults.size() > 0) {
            int originalRiskLevel = valueAsInt(fact.finalResult, Constants.originalRiskLevel);
            //获取最高分
            Map<String, Object> finalResult = Constants.defaultResult;
            for (Map<String, Object> rs : fact.leveldownResults.values()) {
                finalResult = compareAndReturn(finalResult, rs);
            }
            fact.setFinalResult(Maps.newHashMap(finalResult));
            fact.finalResult.put(Constants.originalRiskLevel, originalRiskLevel);
        }
    }

    /**
     * 返回分值高的结果作为finalResult
     */
    static Map<String, Object> compareAndReturn(Map<String, Object> oldResult, Map<String, Object> newResult) {
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
