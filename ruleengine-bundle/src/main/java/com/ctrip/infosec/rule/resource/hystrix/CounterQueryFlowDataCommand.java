/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource.hystrix;

import com.ctrip.infosec.counter.model.FlowQueryRequest;
import com.ctrip.infosec.counter.model.FlowQueryResponse;
import com.ctrip.infosec.counter.venus.FlowPolicyRemoteServiceV2;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.netflix.hystrix.HystrixCommand;
import com.netflix.hystrix.HystrixCommandGroupKey;
import com.netflix.hystrix.HystrixCommandKey;
import com.netflix.hystrix.HystrixCommandProperties;
import com.netflix.hystrix.HystrixThreadPoolProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author zhengby
 */
public class CounterQueryFlowDataCommand extends HystrixCommand<FlowQueryResponse> {

    private static final Logger logger = LoggerFactory.getLogger(CounterQueryFlowDataCommand.class);
    private static final int coreSize = GlobalConfig.getInteger("hystrix.counter.invoke.coreSize", 128);
    private static final int timeout = GlobalConfig.getInteger("hystrix.counter.invoke.timeout", 400);

    private FlowQueryRequest flowQueryRequest;

    public CounterQueryFlowDataCommand(FlowQueryRequest flowQueryRequest, boolean isAsync) {
        super(HystrixCommand.Setter
                .withGroupKey(HystrixCommandGroupKey.Factory.asKey("CounterInvokeGroup"))
                .andCommandKey(HystrixCommandKey.Factory.asKey("CounterInvokeCommand"))
                .andCommandPropertiesDefaults(
                        HystrixCommandProperties.Setter()
                        .withExecutionIsolationThreadTimeoutInMilliseconds(isAsync ? (timeout * 4) : timeout)
                )
                .andThreadPoolPropertiesDefaults(
                        HystrixThreadPoolProperties.Setter()
                        .withCoreSize(isAsync ? (coreSize * 2) : coreSize)
                )
        );

        this.flowQueryRequest = flowQueryRequest;
    }

    @Override
    protected FlowQueryResponse run() throws Exception {
        FlowPolicyRemoteServiceV2 flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteServiceV2.class);
        return flowPolicyRemoteService.queryFlowData(flowQueryRequest);
    }
}
