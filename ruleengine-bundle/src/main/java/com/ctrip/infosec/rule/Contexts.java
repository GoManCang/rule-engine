/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule;

/**
 * 订单处理上下文
 *
 * @author zhengbaiyun
 */
public class Contexts {

    /**
     * 日志前缀
     */
    private static ThreadLocal<String> logPrefix = new ThreadLocal<String>();

    /**
     *
     */
    public static String getLogPrefix() {
        String logPrefixValue = Contexts.logPrefix.get();
        if (logPrefixValue == null) {
            return "";
        } else {
            return logPrefixValue;
        }
    }

    public static void setLogPrefix(String logPrefixValue) {
        Contexts.logPrefix.set(logPrefixValue);
    }

}
