package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.utils.concurrent.MethodProxyFactory;
import com.ctrip.infosec.configs.utils.concurrent.PoolConfig;
import com.ctrip.infosec.configs.utils.concurrent.PooledMethodProxy;
import com.ctrip.infosec.rclient.Rclient;
import com.ctrip.infosec.rule.Contexts;
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
    /**
     * URL前缀, 包含ContextPath部分, 如: http://10.2.10.75:8080/counterws
     */
    static final String rServiceIp = GlobalConfig.getString("RService.Ip");

    static Rclient rclient = null;

    static void check() {
        Validate.notEmpty(rServiceIp, "在GlobalConfig.properties里没有找到\"RService.Ip\"配置项.");
        initRServiceProxy();
    }

    /**
     * 异步模拟同步（多线程）调用DataProxy.
     */
    static PooledMethodProxy RServiceProxy;
    private static final int coreSize = GlobalConfig.getInteger("pooled.sync.coreSize", 32);
    private static final int maxThreadSize = GlobalConfig.getInteger("pooled.sync.maxThreadSize", 512);
    private static final int keepAliveTime = GlobalConfig.getInteger("pooled.sync.keepAliveTime", 60);
    private static final int queueSize = GlobalConfig.getInteger("pooled.sync.queueSize", -1);
    private static Lock lock = new ReentrantLock();

    private static void connect() {
        check();
        try {
            rclient = new Rclient(rServiceIp,1,1);//一个连接，每个规则引擎连接一台机器
            rclient.init();
        } catch (Exception e) {
            logger.warn("连接Rserve异常:" + e.getMessage());
        }
    }

    static void initRServiceProxy() {
        if (RServiceProxy == null) {
            lock.lock();
            try {
                if (RServiceProxy == null) {
                    logger.info(SarsMonitorContext.getLogPrefix() + "init RServiceProxy ...");
                    connect();
                    RService service = SpringContextHolder.getBean(RService.class);
                    PooledMethodProxy proxy = MethodProxyFactory
                            .newMethodProxy(service, "getRScore", String.class)
                            .supportAsyncInvoke()
                            .pooledWithConfig(new PoolConfig()
                                    .withCorePoolSize(coreSize)
                                    .withKeepAliveTime(keepAliveTime)
                                    .withMaxPoolSize(maxThreadSize)
                                    .withQueueSize(queueSize)
                            );
                    RServiceProxy = proxy;
                    logger.info(SarsMonitorContext.getLogPrefix() + "init RServiceProxy ... OK");
                }
            } catch (Exception ex) {
                logger.info(SarsMonitorContext.getLogPrefix() + "init RServiceProxy ... Exception", ex);
            } finally {
                lock.unlock();
            }
        }
    }

    public static double getScore(String expression) {
        initRServiceProxy();
        check();
        beforeInvoke();
        double score = 0.0;
        try {
            score = RServiceProxy.syncInvoke(500, expression);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke RService.getScore fault.", ex);
        } finally {
            afterInvoke("RService.getScore");
        }
        return score;
    }

    public double getRScore(String expression) {
        double score = 0.0;
        try {
            REXP rexp = (REXP)rclient.run(expression);
            score = rexp.asDouble();
        } catch (REXPMismatchException e) {
            logger.warn("获取RServer分数异常:" + e.getMessage());
        }
        return score;
    }
}
