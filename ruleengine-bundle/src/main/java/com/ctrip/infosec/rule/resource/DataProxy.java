/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.ctrip.sec.userprofile.contract.venusapi.DataProxyVenusService;
import com.ctrip.sec.userprofile.vo.content.request.DataProxyRequest;
import com.ctrip.sec.userprofile.vo.content.response.DataProxyResponse;
import com.fasterxml.jackson.databind.JavaType;

import java.util.*;

import com.google.common.collect.Lists;
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

    static final JavaType javaType = JSON.constructCollectionType(List.class, DataProxyResponse.class);

    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.REST.URL.Prefix\"配置项.");
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.Venus.ipAddressList\"配置项.");
    }

    public static Map query(String serviceName, String operationName, Map<String, Object> params) {
        DataProxyRequest request = new DataProxyRequest();
        request.setServiceName(serviceName);
        request.setOperationName(operationName);
        request.setParams(params);
        return queryForFormatValue(request).getResult();
    }

    /**
     * Rest数据查询接口
     *
     * @param request
     * @return
     */
    private static DataProxyResponse queryForFormatValue(DataProxyRequest request) {
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
//        if (response.getRtnCode() == 0
//                && request.getServiceName().equals("UserProfileService")) {
//            if (request.getParams().get("tagName") != null) {
//                Map newResult = getNewResult(response.getResult());
//                response.setResult(newResult);
//            } else if (request.getParams().get("tagNames") != null) {
//                List<Map> oldResults = (List<Map>) response.getResult().get("tagNames");
//                List<Map> newResults = new ArrayList<Map>();
//                Iterator iterator = oldResults.iterator();
//                while (iterator.hasNext()) {
//                    Map oneResult = (Map) iterator.next();
//                    newResults.add(getNewResult(oneResult));
//                }
//                Map finalResult = new HashMap();
//                finalResult.put("result", newResults);
//                response.setResult(finalResult);
//            }
//        }
        return response;
    }

    public static Map queryProfileTagsForMap(String serviceName, String operationName, Map<String, Object> params) {
        Map result = query(serviceName, operationName, params);
        if (params.get("tagName") != null) {
            return getNewResult(result);
        } else if (params.get("tagNames") != null) {
            List<Map> oldResults = (List<Map>) result.get("tagNames");
            Map newResults = new HashMap();
            Iterator iterator = oldResults.iterator();
            while (iterator.hasNext()) {
                Map oneResult = (Map) iterator.next();
                newResults.putAll(oneResult);
            }
            return newResults;
        }
        return null;
    }

    //venus
    /**
     * 查询一个服务的接口
     *
     * @param serviceName
     * @param operationName
     * @param params
     * @return
     */
    public static Map queryForMap(String serviceName, String operationName, Map<String, Object> params) {
        beforeInvoke();
        try {
            DataProxyRequest request = new DataProxyRequest();
            request.setServiceName(serviceName);
            request.setOperationName(operationName);
            request.setParams(params);
            List<DataProxyRequest> requests = new ArrayList<DataProxyRequest>();
            requests.add(request);
            DataProxyVenusService dataProxyVenusService = SpringContextHolder.getBean(DataProxyVenusService.class);
            List<DataProxyResponse> responses = dataProxyVenusService.dataproxyQueries(requests);
            if (responses == null || responses.size() < 1) {
                return new HashMap();
            }
            DataProxyResponse response = responses.get(0);
            if (response.getRtnCode() == 0) {
                return response.getResult();
            } else {
                logger.warn(Contexts.getLogPrefix() + "invoke DataProxy.queryForMap fault. RtnCode=" + response.getRtnCode() + ", RtnMessage=" + response.getMessage());
            }
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke DataProxy.queryForMap fault.", ex);
        } finally {
            afterInvoke("DataProxy.queryForMap");
        }
        return null;
    }

    /**
     * 批量查询的接口
     *
     * @param requests
     * @return
     */
    public static List<Map> queryForList(List<DataProxyRequest> requests) {
        beforeInvoke();
        List<Map> results = new ArrayList<Map>();
        try {
            DataProxyVenusService dataProxyVenusService = SpringContextHolder.getBean(DataProxyVenusService.class);
            List<DataProxyResponse> responses = dataProxyVenusService.dataproxyQueries(requests);
            if (responses == null || responses.size() < 1) {
                return results;
            }
            for (int i = 0; i < responses.size(); i++) {
                //这里得到的结果的顺序和请求的顺序是一致的
                DataProxyRequest request = requests.get(i);
                DataProxyResponse response = responses.get(i);
                if (response.getResult() == null) {
                    results.add(new HashMap());
                    continue;
                }
                if (request.getServiceName().equals("UserProfileService")) {
                    if (request.getParams().get("tagName") != null) {
                        Map newResult = getNewResult(response.getResult());
                        response.setResult(newResult);
                    } else if (request.getParams().get("tagNames") != null) {
                        List<Map> oldResults = (List<Map>) response.getResult().get("tagNames");
                        List<Map> newResults = new ArrayList<Map>();
                        Iterator iterator = oldResults.iterator();
                        while (iterator.hasNext()) {
                            Map oneResult = (Map) iterator.next();
                            newResults.add(getNewResult(oneResult));
                        }
                        Map finalResult = new HashMap();
                        finalResult.put("result", newResults);
                        response.setResult(finalResult);
                    }
                }
                results.add(response.getResult());
            }
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke DataProxy.queryForList fault.", ex);
        } finally {
            afterInvoke("DataProxy.queryForList");
        }
        return results;
    }

    /**
     * 转换数据格式 把从userProfile里面的数据转成Map的格式
     *
     * @param oldValue 原来的值
     * @return
     */
    private static Map getNewResult(Map oldValue) {
        Map newResult = new HashMap();
        String tagDataType = oldValue.get("tagDataType") == null ? "" : oldValue.get("tagDataType").toString();
        if (tagDataType.toLowerCase().equals("int") || tagDataType.toLowerCase().equals("string") || tagDataType.toLowerCase().equals("datetime")
                || tagDataType.toLowerCase().equals("boolean")) {
            String tagName = oldValue.get("tagName") == null ? "" : oldValue.get("tagName").toString();
            String tagContent = oldValue.get("tagContent") == null ? "" : oldValue.get("tagContent").toString();
            newResult.put(tagName, tagContent);
        } else if (tagDataType.toLowerCase().equals("list")) {
            String tagName = oldValue.get("tagName") == null ? "" : oldValue.get("tagName").toString();

            List tagContent = oldValue.get("tagContent") == null ? new ArrayList() : JSON.parseObject(JSON.toJSONString(oldValue.get("tagContent")), List.class);
            newResult.put(tagName, tagContent);
        }
        return newResult;
    }
}
