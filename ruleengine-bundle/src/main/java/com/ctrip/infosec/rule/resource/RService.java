package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.utils.concurrent.MethodProxyFactory;
import com.ctrip.infosec.configs.utils.concurrent.PoolConfig;
import com.ctrip.infosec.configs.utils.concurrent.PooledMethodProxy;
import com.ctrip.infosec.rclient.Rclient;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.hystrix.RServiceCommand;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import org.apache.commons.lang3.Validate;
import org.rosuda.REngine.REXP;
import org.rosuda.REngine.REXPMismatchException;
import org.rosuda.REngine.Rserve.RConnection;
import org.rosuda.REngine.Rserve.RserveException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 15-6-18.
 */
public class RService {

    private static final Logger logger = LoggerFactory.getLogger(RService.class);

    private static RServiceCommand rServiceCommand = null;

    public static double getScore(String expression) {
        beforeInvoke("RService.getScore");
        double score = 0.0;
        try {
            rServiceCommand = SpringContextHolder.getBean(RServiceCommand.class);
            rServiceCommand.setParams(expression);
            score = rServiceCommand.execute();
        } catch (Exception ex) {
            fault("RService.getScore");
            logger.error(Contexts.getLogPrefix() + "invoke RService.getScore fault.", ex);
        } finally {
            afterInvoke("RService.getScore");
        }
        return score;
    }
}
