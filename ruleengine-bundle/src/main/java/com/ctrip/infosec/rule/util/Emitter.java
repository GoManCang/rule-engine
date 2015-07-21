/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.util;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.counter.model.CounterRuleExecuteResult;
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
     * 合并CounterServer的规则结果
     */
    public static void mergeCounterResults(RiskFact fact, List<CounterRuleExecuteResult> ruleExecuteResults) {
//        String _ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        Boolean _isAsync = MapUtils.getBoolean(fact.ext, Constants.key_isAsync);
        if (ruleExecuteResults != null && !ruleExecuteResults.isEmpty()) {

            for (CounterRuleExecuteResult ruleExecuteResult : ruleExecuteResults) {
                if (StringUtils.isNotBlank(ruleExecuteResult.getRuleNo())
                        && StringUtils.isNumeric(ruleExecuteResult.getResultCode())) {

                    int riskLevel = NumberUtils.toInt(ruleExecuteResult.getResultCode(), 0);
                    if (riskLevel > 0) {
                        Map<String, Object> result = Maps.newHashMap();
                        result.put(Constants.riskLevel, riskLevel);
                        result.put(Constants.riskMessage, ruleExecuteResult.getResultMessage());
                        if (_isAsync != null) {
                            result.put(Constants.async, _isAsync);
                        }

                        if (StringUtils.isBlank(ruleExecuteResult.getScenes())) {
                            fact.results.put(ruleExecuteResult.getRuleNo(), result);
                        } else {
                            List<String> riskScenes = Splitter.on(",").omitEmptyStrings().trimResults().splitToList(ruleExecuteResult.getScenes());
                            result.put(Constants.riskScene, riskScenes);
                            fact.resultsGroupByScene.put(ruleExecuteResult.getRuleNo(), result);
                        }
                    }
                }
            }
        }
    }
}
