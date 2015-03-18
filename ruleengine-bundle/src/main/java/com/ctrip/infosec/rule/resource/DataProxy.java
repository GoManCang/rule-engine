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
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.fasterxml.jackson.databind.JavaType;
import java.util.List;
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
public class DataProxy {

    private static final Logger logger = LoggerFactory.getLogger(DataProxy.class);
    /**
     * URL前缀, 包含ContextPath部分, 如: http://10.2.10.75:8080/counterws
     */
    static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");

    final JavaType javaType = JSON.constructCollectionType(List.class, DataProxyResponse.class);

    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.REST.URL.Prefix\"配置项.");
    }

    /**
     * 数据查询接口
     *
     * @param request
     * @return
     */
    public DataProxyResponse query(DataProxyRequest request) {
        check();
        DataProxyResponse response = null;
        try {
            String responseTxt = Request.Post(urlPrefix + "/rest/dataproxy/query")
                    .body(new StringEntity(JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .execute().returnContent().asString();
            response = JSON.parseObject(responseTxt, DataProxyResponse.class);
            return response;
        } catch (Exception ex) {
            logger.error(Contexts.getLogPrefix() + "invoke DataProxy.query fault.", ex);
            return null;
        }
    }

    /**
     * 数据查询接口
     */
    public List<DataProxyResponse> queries(List<DataProxyRequest> request) {
        check();
        List<DataProxyResponse> response = null;
        try {
            String responseTxt = Request.Post(urlPrefix + "/rest/dataproxy/queries")
                    .body(new StringEntity(JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(1000).socketTimeout(5000)
                    .execute().returnContent().asString();
            response = JSON.parseObject(responseTxt, javaType);
            return response;
        } catch (Exception ex) {
            logger.error(Contexts.getLogPrefix() + "invoke DataProxy.queries fault.", ex);
            return null;
        }
    }

}
