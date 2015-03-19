/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.util;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.common.Constants;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import java.util.Map;

/**
 *
 * @author zhengby
 */
public class Emitter {

    public static void emit(RiskFact fact, int riskLevel, String riskMessage) {
        String ruleNo = (String) fact.ext.get(Constants.key_ruleNo);
        if (!Strings.isNullOrEmpty(ruleNo)) {
            Map<String, Object> result = Maps.newHashMap();
            result.put(Constants.riskLevel, riskLevel);
            result.put(Constants.riskMessage, riskMessage);
            fact.results.put(ruleNo, result);
        }
    }
}
