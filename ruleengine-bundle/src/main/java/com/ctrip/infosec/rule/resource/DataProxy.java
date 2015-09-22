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
import com.ctrip.infosec.rule.resource.hystrix.DataProxyQueryCommand;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.sec.userprofile.vo.content.request.DataProxyRequest;
import com.google.common.collect.ImmutableMap;

import java.util.*;

import org.apache.commons.lang3.Validate;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
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
    private static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");

    private static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.REST.URL.Prefix\"配置项.");
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.Venus.ipAddressList\"配置项.");
    }

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
        beforeInvoke("DataProxy.queryForMap");
        beforeInvoke("DataProxy." + serviceName + "." + operationName);
        try {
            DataProxyQueryCommand command = new DataProxyQueryCommand(serviceName, operationName, params);
            Map newResult = command.execute();
            if (serviceName.equals("UserProfileService")) {
                newResult = parseProfileResult(newResult);
            }
            return newResult;
        } catch (Exception ex) {
            fault("DataProxy.queryForMap");
            fault("DataProxy." + serviceName + "." + operationName);
            logger.error(Contexts.getLogPrefix() + "invoke DataProxy.queryForMap fault.", ex);
        } finally {
            afterInvoke("DataProxy.queryForMap");
            afterInvoke("DataProxy." + serviceName + "." + operationName);
        }
        return Collections.EMPTY_MAP;
    }

    /**
     * 查询userProfiles的接口
     */
    public static Map<String, Object> queryTags(String profile, String value, List<String> tagNames) {
        String serviceName = "UserProfileService";
        String operationName = "DataQuery";
        Map params = ImmutableMap.of(profile, value, "tagNames", tagNames);
        return queryForMap(serviceName, operationName, params);
    }

    /**
     *
     * @param key 定义的tag关联字段的值
     * @param values tag的名称和这个tag对应的值组成的map example:key:uid-123
     * values:RECENT_IP-112.23.32.36 RECENT_IPAREA-大连
     * -------------------------------------
     *
     * 调用的方式是： temp = new
     * HashMap();temp.put("RECENT_IP","112.23.32.36");temp.put("RECENT_IPAREA","大连");
     * addTagData("123",temp)
     * @return 如果写入成功则返回true，否则false
     */
    public static boolean addTagData(String key, Map<String, String> values) {
        boolean flag = false;
        check();
        beforeInvoke("DataProxy.addTagData");
        try {
            List<DataProxyRequest> requests = new ArrayList<>();
            DataProxyRequest request = new DataProxyRequest();
            request.setServiceName("CommonService");
            request.setOperationName("addData");

            Map params = new HashMap<String, String>();
            params.put("tableName", "UserProfileInfo");
            params.put("pkValue", key.trim());
            params.put("storageType", "1");
            params.put("values", values);
            request.setParams(params);
            requests.add(request);
            String requestText = JSON.toPrettyJSONString(requests);
            String responseText = Request.Post(urlPrefix + "/rest/dataproxy/dataprocess").
                    bodyString(requestText, ContentType.APPLICATION_JSON).execute().returnContent().asString();
            Map result = JSON.parseObject(responseText, Map.class);
            if (result.get("rtnCode").equals("0")) {
                flag = true;
            } else {
                flag = false;
                logger.warn("添加数据:" + JSON.toPrettyJSONString(values) + "\t" + "到userProfile失败!");
            }
        } catch (Exception ex) {
            fault("DataProxy.addTagData");
            logger.error(Contexts.getLogPrefix() + "invoke DataProxy.addTagData fault.", ex);
        } finally {
            afterInvoke("DataProxy.addTagData");
        }
        return flag;
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
        return Collections.EMPTY_MAP;
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

    /**
     * 同盾的ip和手机号交易事件查询服务
     *
     * @param ip
     * @param mobile
     * @return
     * {"reason_code":null,"final_decision":"Accept","seq_id":"1442309654522-72705995","final_score":0,"success":true}
     */
    @Deprecated
    public static Map queryForTongDunT(String ip, String mobile) {
        return TongDun.queryTradeEvent(ip, mobile);
    }

    /**
     * 同盾的ip和手机号注册事件查询服务
     *
     * @param ip
     * @param mobile
     * @return
     * {"reason_code":null,"final_decision":"Accept","seq_id":"1442309654522-72705995","final_score":0,"success":true}
     */
    @Deprecated
    public static Map queryForTongDunR(String ip, String mobile) {
        return TongDun.queryRegEvent(ip, mobile);
    }

    /**
     * 凯安的ip和手机号注册事件查询服务
     *
     * @param ip
     * @param mobile
     * @return
     * {"msg":null,"success":1,"mobile":{"score":null,"is_notreal":null},"ip":{"is_proxy":0,"score":50.0,"ip":"218.17.231.209"}}
     */
    @Deprecated
    public static Map queryForKaiAn(String ip, String mobile) {
        return QiAn.queryRegEvent(ip, mobile);
    }
}
