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
import com.ctrip.infosec.configs.utils.concurrent.MethodProxyFactory;
import com.ctrip.infosec.configs.utils.concurrent.PoolConfig;
import com.ctrip.infosec.configs.utils.concurrent.PooledMethodProxy;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import com.ctrip.sec.userprofile.contract.venusapi.DataProxyVenusService;
import com.ctrip.sec.userprofile.vo.content.request.DataProxyRequest;
import com.ctrip.sec.userprofile.vo.content.response.DataProxyResponse;
import com.fasterxml.jackson.databind.JavaType;

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

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
        initDataProxyVenusServiceProxy();
    }

    /**
     * 异步模拟同步（多线程）调用DataProxy.
     */
    static PooledMethodProxy dataProxyVenusServiceProxy;
    private static final int coreSize = GlobalConfig.getInteger("pooled.sync.coreSize", 32);
    private static final int maxThreadSize = GlobalConfig.getInteger("pooled.sync.maxThreadSize", 512);
    private static final int keepAliveTime = GlobalConfig.getInteger("pooled.sync.keepAliveTime", 60);
    private static final int queueSize = GlobalConfig.getInteger("pooled.sync.queueSize", -1);
    private static final int queryTimeout = GlobalConfig.getInteger("DataProxy.query.timeout", 500);
    private static Lock lock = new ReentrantLock();

    /**
     * 初始化DataProxy执行的POOL
     */
    static void initDataProxyVenusServiceProxy() {
        if (dataProxyVenusServiceProxy == null) {
            lock.lock();
            try {
                if (dataProxyVenusServiceProxy == null) {
                    logger.info(SarsMonitorContext.getLogPrefix() + "init data proxy client ...");
                    DataProxyVenusService service = SpringContextHolder.getBean(DataProxyVenusService.class);
                    PooledMethodProxy proxy = MethodProxyFactory
                            .newMethodProxy(service, "dataproxyQueries", List.class)
                            .supportAsyncInvoke()
                            .pooledWithConfig(new PoolConfig()
                                    .withCorePoolSize(coreSize)
                                    .withKeepAliveTime(keepAliveTime)
                                    .withMaxPoolSize(maxThreadSize)
                                    .withQueueSize(queueSize)
                            );
                    dataProxyVenusServiceProxy = proxy;
                    logger.info(SarsMonitorContext.getLogPrefix() + "init data proxy client ... OK");
                }
            } catch (Exception ex) {
                logger.info(SarsMonitorContext.getLogPrefix() + "init data proxy client ... Exception", ex);
            } finally {
                lock.unlock();
            }
        }
    }

    public static Map query(String serviceName, String operationName, Map<String, Object> params) {
        DataProxyRequest request = new DataProxyRequest();
        request.setServiceName(serviceName);
        request.setOperationName(operationName);
        request.setParams(params);
        DataProxyResponse response = query(request);
        if (response.getRtnCode() != 0) {
            logger.warn(Contexts.getLogPrefix() + "invoke DataProxy.query fault. RtnCode=" + response.getRtnCode() + ", RtnMessage=" + response.getMessage());
            return null;
        }

        Map newResult = null;
        if (request.getServiceName().equals("UserProfileService")) {
            newResult = parseProfileResult(response.getResult());
        } else {
            newResult = response.getResult();
        }
        return newResult;
    }

    /**
     * Rest数据查询接口
     *
     * @param request
     * @return
     */
    private static DataProxyResponse query(DataProxyRequest request) {
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
     * 查询userProfiles的接口
     *
     * @param serviceName
     * @param operationName
     * @param params
     * @return
     */
    public static Map queryProfileTagsForMap(String serviceName, String operationName, Map<String, Object> params) {
        Map result = queryForMap(serviceName, operationName, params);
        if (params.get("tagName") != null) {
            return parseResult(result);
        } else if (params.get("tagNames") != null) {
            List<Map> oldResults = (List<Map>) result.get("tagNames");
            Map newResults = new HashMap();
            Iterator iterator = oldResults.iterator();
            while (iterator.hasNext()) {
                Map oneResult = (Map) iterator.next();
                newResults.putAll(parseResult(oneResult));
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
        check();
        beforeInvoke();
        beforeInvoke("DataProxy." + serviceName + "." + operationName);
        try {
            DataProxyRequest request = new DataProxyRequest();
            request.setServiceName(serviceName);
            request.setOperationName(operationName);
            request.setParams(params);
            List<DataProxyRequest> requests = new ArrayList<DataProxyRequest>();
            requests.add(request);

//            DataProxyVenusService dataProxyVenusService = SpringContextHolder.getBean(DataProxyVenusService.class);
//            List<DataProxyResponse> responses = dataProxyVenusService.dataproxyQueries(requests);
            List<DataProxyResponse> responses = dataProxyVenusServiceProxy.syncInvoke(queryTimeout, requests);

            if (responses == null || responses.size() < 1) {
                return new HashMap();
            }
            DataProxyResponse response = responses.get(0);
            if (response.getRtnCode() != 0) {
                logger.warn(Contexts.getLogPrefix() + "invoke DataProxy.queryForMap fault. RtnCode=" + response.getRtnCode() + ", RtnMessage=" + response.getMessage());
                return null;
            }

            Map newResult = null;
            if (request.getServiceName().equals("UserProfileService")) {
                newResult = parseProfileResult(response.getResult());
            } else {
                newResult = response.getResult();
            }
            return newResult;

        } catch (Exception ex) {
        	fault();
        	fault("DataProxy." + serviceName + "." + operationName);
        	logger.error(Contexts.getLogPrefix() + "invoke DataProxy.queryForMap fault.", ex);
        } finally {
            afterInvoke("DataProxy.queryForMap");
            afterInvoke("DataProxy." + serviceName + "." + operationName);
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
        check();
        beforeInvoke();
        List<Map> results = new ArrayList<Map>();
        try {
            DataProxyVenusService dataProxyVenusService = SpringContextHolder.getBean(DataProxyVenusService.class);
            List<DataProxyResponse> responses = dataProxyVenusService.dataproxyQueries(requests);
            if (responses == null || responses.isEmpty()) {
                return results;
            }
            for (int i = 0; i < responses.size(); i++) {

                //这里得到的结果的顺序和请求的顺序是一致的
                DataProxyRequest request = requests.get(i);
                DataProxyResponse response = responses.get(i);

                if (response.getRtnCode() != 0) {
                    logger.warn(Contexts.getLogPrefix() + "invoke DataProxy.queryForList[" + i + "] fault. RtnCode=" + response.getRtnCode() + ", RtnMessage=" + response.getMessage());
                    continue;
                }

                Map newResult = null;
                if (request.getServiceName().equals("UserProfileService")) {
                    newResult = parseProfileResult(response.getResult());
                } else {
                    newResult = response.getResult();
                }
                if (newResult != null) {
                    results.add(newResult);
                }
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
     * 转换DataProxyResponse对象的result为Map
     */
    private static Map parseProfileResult(Map result) {
        if (result != null) {
            if (result.get("tagName") != null) {
                return parseResult(result);
            } else if (result.get("tagNames") != null) {
                Object tagValues = result.get("tagNames");
                List oldResults = JSON.parseObject(JSON.toJSONString(tagValues), List.class);
                Map newResults = new HashMap();
                Iterator iterator = oldResults.iterator();
                while (iterator.hasNext()) {
                    Map oneResult = (Map) iterator.next();
                    newResults.putAll(parseResult(oneResult));
                }
                return newResults;
            } else {
                return result;
            }
        }
        return null;
    }

    /**
     * 转换数据格式 把从userProfile里面的数据转成Map的格式
     */
    private static Map parseResult(Map oldValue) {
        Map newResult = new HashMap();
        String tagDataType = oldValue.get("tagDataType") == null ? "" : oldValue.get("tagDataType").toString();
        if (tagDataType.toLowerCase().equals("int")
                || tagDataType.toLowerCase().equals("string")
                || tagDataType.toLowerCase().equals("datetime")
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
