/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.util;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.ctrip.infosec.sars.monitor.counters.CounterRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author zhengby
 */
public class MonitorAgent {

    private static final Logger logger = LoggerFactory.getLogger(MonitorAgent.class);
    protected static ThreadLocal<Boolean> faultHolder = new ThreadLocal<Boolean>();
    protected static ThreadLocal<Long> beginTimeHolder = new ThreadLocal<Long>();

    protected static void beforeInvoke() {
        beginTimeHolder.set(System.currentTimeMillis());
    }

    protected static void fault() {
        faultHolder.set(Boolean.TRUE);
    }

    protected static void afterInvoke(String operation) {
        long beginTime = beginTimeHolder.get();
        long endTime = System.currentTimeMillis();
        long handlingTime = endTime - beginTime;

        Boolean isFault = faultHolder.get();
        if (isFault == null) {
            isFault = Boolean.FALSE;
        }

        CounterRepository.increaseCounter(operation, handlingTime, isFault);

        // logger
        if (handlingTime < SarsMonitorContext.WARN_VALUE) {
            logger.info(Contexts.getLogPrefix() + "invoke " + operation + ", usage=" + handlingTime + "ms");
        } else {
            logger.warn(Contexts.getLogPrefix() + "invoke " + operation + ", usage=" + handlingTime + "ms");
        }
    }
}
