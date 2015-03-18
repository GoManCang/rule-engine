/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule;

import com.google.common.collect.ImmutableMap;
import java.util.Map;

/**
 * 常量
 *
 * @author zhengbaiyun
 */
public class Constants {

    /**
     * 常用的KEY定义
     */
    public static final String key_eventId = "_eventId";
    public static final String key_ruleNo = "_ruleNo";
    /**
     * 规则执行结果的KEY
     */
    public static final String riskLevel = "riskLevel";
    public static final String riskMessage = "riskMessage";
    public static final String async = "async";
    public static final String timeUsage = "timeUsage";

    public static final Map defaultResult = ImmutableMap.of(riskLevel, 0, riskMessage, "PASS");

}
