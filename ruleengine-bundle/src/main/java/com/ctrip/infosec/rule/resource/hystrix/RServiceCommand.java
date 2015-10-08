package com.ctrip.infosec.rule.resource.hystrix;

import com.ctrip.infosec.rclient.Rclient;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.netflix.hystrix.*;
import org.apache.commons.lang3.Validate;
import org.rosuda.REngine.REXP;
import org.rosuda.REngine.REXPMismatchException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Created by lpxie on 15-10-8.
 */
public class RServiceCommand extends HystrixCommand<Double> {
    private static Logger logger = LoggerFactory.getLogger(RServiceCommand.class);
    //刚开始调用R服务的量在200左右 ，200*0.2=40 50个比较合适
    private static int coreSize = 50;
    private static int timeOut = 500;

    /**
     * URL前缀, 包含ContextPath部分, 如: http://10.2.10.75:8080/counterws
     */
    static final String rServiceIp = GlobalConfig.getString("RService.Ip");
    static Rclient rclient = null;

    static void check() {
        Validate.notEmpty(rServiceIp, "在GlobalConfig.properties里没有找到\"RService.Ip\"配置项.");
    }

    private static void init(){
        check();
        try {
            rclient = new Rclient(rServiceIp, 1, 1);//一个连接，每个规则引擎连接一台机器
            rclient.init();
        } catch (Exception e) {
            logger.warn("连接Rserve异常:" + e.getMessage());
        }
    }

    private String expression = "";

    public RServiceCommand()
    {
        super(HystrixCommand.Setter
                .withGroupKey(HystrixCommandGroupKey.Factory.asKey("RServiceGroup"))
                .andCommandKey(HystrixCommandKey.Factory.asKey("RServiceCommand"))
                .andCommandPropertiesDefaults(HystrixCommandProperties.Setter().withExecutionIsolationThreadTimeoutInMilliseconds(timeOut))
                .andThreadPoolPropertiesDefaults(HystrixThreadPoolProperties.Setter().withCoreSize(coreSize))
        );
    }

    public void setParams(String expression)
    {
        this.expression = expression;
    }
    /**
     * 真正的业务逻辑
     * @return
     * @throws Exception
     */
    @Override
    protected Double run() throws Exception {
        double score = 0.0;
        try {
            REXP rexp = (REXP) rclient.run(expression);
            score = rexp.asDouble();
        } catch (REXPMismatchException e) {
            logger.warn("获取RServer分数异常:" + e.getMessage());
        }
        return score;
    }
}
