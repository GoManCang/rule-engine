/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource.hystrix;

import com.ctrip.infosec.counter.model.PolicyExecuteRequest;
import com.ctrip.infosec.counter.model.PolicyExecuteResponse;
import static com.ctrip.infosec.counter.util.Utils.JSON;
import com.ctrip.infosec.counter.venus.FlowPolicyRemoteService;
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
public class CounterExecuteCommand extends HystrixCommand<PolicyExecuteResponse> {

    private static final Logger logger = LoggerFactory.getLogger(CounterExecuteCommand.class);
    private static final int coreSize = GlobalConfig.getInteger("hystrix.counter.invoke.coreSize", 128);
    private static final int timeout = GlobalConfig.getInteger("hystrix.counter.invoke.timeout", 400);

    private PolicyExecuteRequest policyExecuteRequest;

    public CounterExecuteCommand(PolicyExecuteRequest policyExecuteRequest, boolean isAsync) {
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

        this.policyExecuteRequest = policyExecuteRequest;
    }

    @Override
    protected PolicyExecuteResponse run() throws Exception {
        FlowPolicyRemoteService flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteService.class);
        String responseTxt = flowPolicyRemoteService.execute(policyExecuteRequest.toJSONString());
        return JSON.parseObject(responseTxt, PolicyExecuteResponse.class);
    }
}
