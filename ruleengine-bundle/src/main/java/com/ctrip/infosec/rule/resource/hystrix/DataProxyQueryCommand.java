/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource.hystrix;

import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.ctrip.sec.userprofile.contract.venusapi.DataProxyVenusService;
import com.ctrip.sec.userprofile.vo.content.request.DataProxyRequest;
import com.ctrip.sec.userprofile.vo.content.response.DataProxyResponse;
import com.netflix.hystrix.HystrixCommand;
import com.netflix.hystrix.HystrixCommandGroupKey;
import com.netflix.hystrix.HystrixCommandKey;
import com.netflix.hystrix.HystrixCommandProperties;
import com.netflix.hystrix.HystrixThreadPoolProperties;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author zhengby
 */
public class DataProxyQueryCommand extends HystrixCommand<Map<String, Object>> {

    private static final Logger logger = LoggerFactory.getLogger(DataProxyQueryCommand.class);
    private static final int coreSize = GlobalConfig.getInteger("hystrix.dataproxy.query.coreSize", 64);
    private static final int timeout = GlobalConfig.getInteger("hystrix.dataproxy.query.timeout", 500);

    private static final String VENUS = "VENUS";
    private static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");
    private static final String apiMode = GlobalConfig.getString("DataProxy.API.MODE", VENUS);

    private String serviceName;
    private String operationName;
    private Map<String, Object> params;

    public DataProxyQueryCommand(String serviceName, String operationName, Map<String, Object> params) {
        super(HystrixCommand.Setter
                .withGroupKey(HystrixCommandGroupKey.Factory.asKey("DataProxyQueryGroup"))
                .andCommandKey(HystrixCommandKey.Factory.asKey("DataProxyQueryCommand"))
                .andCommandPropertiesDefaults(
                        HystrixCommandProperties.Setter()
                        .withExecutionIsolationThreadTimeoutInMilliseconds(timeout)
                )
                .andThreadPoolPropertiesDefaults(
                        HystrixThreadPoolProperties.Setter()
                        .withCoreSize(coreSize)
                )
        );

        this.serviceName = serviceName;
        this.operationName = operationName;
        this.params = params;
    }

    @Override
    protected Map<String, Object> run() throws Exception {

        DataProxyRequest request = new DataProxyRequest();
        request.setServiceName(serviceName);
        request.setOperationName(operationName);
        request.setParams(params);

        List<DataProxyRequest> requests = new ArrayList<>();
        requests.add(request);

        DataProxyResponse response = null;
        if (VENUS.equals(apiMode)) {
            DataProxyVenusService dataProxyVenusService = SpringContextHolder.getBean(DataProxyVenusService.class);
            List<DataProxyResponse> responses = dataProxyVenusService.dataproxyQueries(requests);
            if (responses == null || responses.size() < 1) {
                return null;
            }
            response = responses.get(0);
            if (response.getRtnCode() != 0) {
                logger.warn(Contexts.getLogPrefix() + "invoke DataProxy.queryForMap fault. RtnCode=" + response.getRtnCode() + ", RtnMessage=" + response.getMessage());
                return null;
            }
        } else {
            String responseTxt = Request.Post(urlPrefix + "/rest/dataproxy/query")
                    .body(new StringEntity(JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .execute().returnContent().asString();
            response = JSON.parseObject(responseTxt, DataProxyResponse.class);
        }

        if (response != null) {
            if (response.getRtnCode() == 0) {
                return response.getResult();
            } else {
                logger.warn(Contexts.getLogPrefix() + "查询DataProxy异常. RtnCode=" + response.getRtnCode() + ", RtnMessage=" + response.getMessage());
            }
        }
        return Collections.EMPTY_MAP;
    }

    @Override
    protected Map<String, Object> getFallback() {
        logger.warn("查询DataProxy超时或异常.");
        return Collections.EMPTY_MAP;
    }
}
