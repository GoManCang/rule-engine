/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource.hystrix;

import com.ctrip.infosec.counter.model.ListRepoBooleanResponse;
import com.ctrip.infosec.counter.model.ListRepoQueryRequest;
import com.ctrip.infosec.counter.venus.ListRepoRemoteService;
import com.ctrip.infosec.counter.venus.ListRepoRemoteServiceV2;
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
public class ListRepoQueryCommand extends HystrixCommand<ListRepoBooleanResponse> {

    private static final Logger logger = LoggerFactory.getLogger(ListRepoQueryCommand.class);
    private static final int coreSize = GlobalConfig.getInteger("hystrix.listRepo.invoke.coreSize", 64);
    private static final int timeout = GlobalConfig.getInteger("hystrix.listRepo.invoke.timeout", 200);

    private String method;
    private ListRepoQueryRequest listRepoQueryRequest;
    private static final String isIn = "isIn";
    private static final String isAnyIn = "isAnyIn";
    private static final String isAllIn = "isAllIn";

    public ListRepoQueryCommand(String method, ListRepoQueryRequest listRepoQueryRequest) {
        super(HystrixCommand.Setter
                .withGroupKey(HystrixCommandGroupKey.Factory.asKey("ListRepoInvokeGroup"))
                .andCommandKey(HystrixCommandKey.Factory.asKey("ListRepoInvokeCommand"))
                .andCommandPropertiesDefaults(
                        HystrixCommandProperties.Setter()
                        .withExecutionIsolationThreadTimeoutInMilliseconds(timeout)
                )
                .andThreadPoolPropertiesDefaults(
                        HystrixThreadPoolProperties.Setter()
                        .withCoreSize(coreSize)
                )
        );

        this.method = method;
        this.listRepoQueryRequest = listRepoQueryRequest;
    }

    @Override
    protected ListRepoBooleanResponse run() throws Exception {
        ListRepoRemoteService listRepoRemoteService = SpringContextHolder.getBean(ListRepoRemoteService.class);
//        ListRepoRemoteServiceV2 listRepoRemoteService = SpringContextHolder.getBean(ListRepoRemoteServiceV2.class);
        if (isIn.equals(method)) {
            return listRepoRemoteService.isIn(listRepoQueryRequest.getRepo(), listRepoQueryRequest.getValue());
        } else if (isAnyIn.equals(method)) {
            return listRepoRemoteService.isAnyIn(listRepoQueryRequest.getRepo(), listRepoQueryRequest.getValues());
        } else if (isAllIn.equals(method)) {
            return listRepoRemoteService.isAllIn(listRepoQueryRequest.getRepo(), listRepoQueryRequest.getValues());
        } else {
            throw new UnsupportedOperationException("不支持的方法: [" + method + "]");
        }
    }
}
