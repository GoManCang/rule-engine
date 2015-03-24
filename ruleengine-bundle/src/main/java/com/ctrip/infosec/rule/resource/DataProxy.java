/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.model.DataProxyRequest;
import com.ctrip.infosec.rule.model.DataProxyResponse;
import com.ctrip.infosec.rule.util.MonitorAgent;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.fasterxml.jackson.databind.JavaType;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.Validate;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author zhengby
 */
public class DataProxy extends MonitorAgent {

    private static final Logger logger = LoggerFactory.getLogger(DataProxy.class);
    /**
     * URL前缀, 包含ContextPath部分, 如: http://10.2.10.75:8080/counterws
     */
    static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");

    static final JavaType javaType = JSON.constructCollectionType(List.class, DataProxyResponse.class);

    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.REST.URL.Prefix\"配置项.");
    }

    /**
     * 数据查询接口
     */
    public static DataProxyResponse query(DataProxyRequest request) {
        check();
        beforeInvoke();
        DataProxyResponse response = null;
        try {
            String responseTxt = Request.Post(urlPrefix + "/rest/dataproxy/query")
                    .body(new StringEntity(JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .execute().returnContent().asString();
            response = JSON.parseObject(responseTxt, DataProxyResponse.class);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke DataProxy.query fault.", ex);
        } finally {
            afterInvoke("DataProxy.query");
        }
        return response;
    }

    /**
     * 数据查询接口（同上）
     *
     * @param serviceName
     * @param operationName
     * @param params
     * @return
     */
    public static DataProxyResponse query(String serviceName, String operationName, Map<String, Object> params) {
        DataProxyRequest request = new DataProxyRequest(serviceName, operationName, params);
        return query(request);
    }

    /**
     * 数据查询接口
     */
    public static List<DataProxyResponse> queries(List<DataProxyRequest> request) {
        check();
        beforeInvoke();
        List<DataProxyResponse> response = null;
        try {
            String responseTxt = Request.Post(urlPrefix + "/rest/dataproxy/queries")
                    .body(new StringEntity(JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(1000).socketTimeout(5000)
                    .execute().returnContent().asString();
            response = JSON.parseObject(responseTxt, javaType);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke DataProxy.queries fault.", ex);
        } finally {
            afterInvoke("DataProxy.queries");
        }
        return response;
    }

}
