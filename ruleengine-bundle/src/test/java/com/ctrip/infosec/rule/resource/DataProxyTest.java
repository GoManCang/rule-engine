/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.sec.userprofile.vo.content.request.DataProxyRequest;
import com.ctrip.sec.userprofile.vo.content.response.DataProxyResponse;
import com.google.common.collect.ImmutableMap;
import com.meidusa.fastjson.JSON;

import java.io.IOException;
import java.util.*;

import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.Ignore;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class DataProxyTest {

    /**
     * 根据ip地址获取相关的信息
     */
    @Test
    public void testQuery() {
        //测试rest接口的DataProxy查询

//        System.out.println("query");
//        String serviceName = "IpService";
//        String operationName = "getIpArea";
//        Map params = ImmutableMap.of("ip", "202.96.209.133");
//        Map result = DataProxy.query(serviceName, operationName, params);
//        System.out.println(result.size());

         /*String serviceName1 = "MobilePhoneService";
         String operationName1 = "getMobileArea";
         Map params1 = ImmutableMap.of("mobileNumber", "013910182539");
         Map result1 = DataProxy.queryForMap(serviceName1, operationName1, params1);
         System.out.println("result1: " + JSON.toJSONString(result1));*/

        /*String serviceName = "CRMService";
         String operationName = "getMemberInfo";
         Map params = ImmutableMap.of("uid", "wwwwww");
         Map result = DataProxy.queryForMap(serviceName, operationName, params);*/

        /*String serviceName = "AirPortService";
         String operationName = "getAirPortCity";
         Map params = ImmutableMap.of("airport", "PEK");
         Map result = DataProxy.queryForMap(serviceName, operationName, params);*/


         /*String serviceName = "UserProfileService";
         String operationName = "DataQuery";
         List tagContents = new ArrayList();
         tagContents.add("CUSCHARACTER");
         Map params = ImmutableMap.of("uid", "wwwwww","tagNames",tagContents);
         Map result = DataProxy.query(serviceName, operationName, params);
         System.out.println(JSON.toJSONString(result));*/

        /*String operationName = "getAirPortCity";
         Map params = ImmutableMap.of("airport", "PEK");
         DataProxyResponse result = DataProxy.query(serviceName, operationName, params);
         Map result1 = result.getResult();*/

        /* String serviceName = "UserProfileService";
         String operationName = "DataQuery";
         List tagContents = new ArrayList();
         tagContents.add("RECENT_IP");
         tagContents.add("RECENT_IPAREA");
         Map params = ImmutableMap.of("uid", "wwwwww","tagNames",tagContents);
         Map result = DataProxy.queryProfileTagsForMap(serviceName, operationName, params);
         System.out.println(JSON.toJSONString(result));*/

        /*String serviceName = "UserProfileService";
         String operationName = "DataQuery";
         //http://userprofile.infosec.ctripcorp.com/userprofileweb/;jsessionid=11099F242AD077BD1F8A53F60FA6E68B
         Map params = ImmutableMap.of("uid", "wwwwww","tagName","RECENT_IP");//STATUS  RECENT_IP
         Map result = DataProxy.queryForMap(serviceName, operationName, params);
         System.out.println(result.size());*/

        /*Map params = new HashMap();
         params.put("cardInfoId", "30075005");
         Map map = CardInfo.query("getinfo", params);
         System.out.println(map.size());*/

        //通过Venus的查询DataProxy
        String serviceName1 = "IDCardInfoService";
        String operationName1 = "getIDCardInfo";
        Map params1 = ImmutableMap.of("idCard", "130100");
        Map result1 = DataProxy.queryForMap(serviceName1, operationName1, params1);
        System.out.println("result1: " + JSON.toJSONString(result1));
    }

    @Test
    //@Ignore
    public void testDataProxyVenus() {
         /*String serviceName = "IpService";
        String operationName = "getIpArea";
        Map params = ImmutableMap.of("ip", "202.96.209.133");
        Map result = DataProxy.queryForMap(serviceName, operationName, params);
        System.out.println(result.size());*/

        /*String serviceName = "ConvertService";
        String operationName = "getBranchCityByBranchNO";
        Map params = ImmutableMap.of("branchno", "011");
        Map result = DataProxy.queryForMap(serviceName, operationName, params);*/

        String serviceName = "ConvertService";
        String operationName = "getCityNameByCityId";
        Map params = ImmutableMap.of("cityId", "2");
        Map result = DataProxy.queryForMap(serviceName, operationName, params);

        /*String serviceName = "UserProfileService";
         String operationName = "DataQuery";
         List tagContents = new ArrayList();
         tagContents.add("RECENT_IP");
         tagContents.add("RECENT_IPAREA");
         Map params = ImmutableMap.of("uid", "wwwwww", "tagNames", tagContents);
         Map result = DataProxy.queryForMap(serviceName, operationName, params);
         System.out.println(result.size());*/

        /*String serviceName = "UserProfileService";
        String operationName = "DataQuery";
        List tagContents = new ArrayList();
        tagContents.add("QIANBAO_IDNO");
        tagContents.add("RECENT_IP");
        Map params = ImmutableMap.of("uid", "D162240074", "tagNames", tagContents);
        Map result = DataProxy.queryForMap(serviceName, operationName, params);
        System.out.println(result.size());*/

        //查询是否为商旅用户
        /*String serviceName = "UserProfileService";
        String operationName = "DataQuery";
        List tagContents = new ArrayList();
        tagContents.add("ISCORP");
        Map params = ImmutableMap.of("uid", "2102819519", "tagNames", tagContents);
        Map result = DataProxy.query(serviceName, operationName, params);
        System.out.println(result.size());*/



        /*String serviceName = "UserProfileService";
         String operationName = "DataQuery";
         List tagContents = new ArrayList();
         tagContents.add("MOB_BOUND");
         tagContents.add("RECENT_IP");
         Map params = ImmutableMap.of("uid", "wwwwww", "tagNames", tagContents);
         Map result = DataProxy.queryForMap(serviceName, operationName, params);
         System.out.println(result.size());*/

        /*String serviceName = "UserProfileService";
         String operationName = "DataQuery";
         //http://userprofile.infosec.ctripcorp.com/userprofileweb/;jsessionid=11099F242AD077BD1F8A53F60FA6E68B
         Map params = ImmutableMap.of("uid", "wwwwww","tagName","RECENT_IP");//STATUS  RECENT_IP
         Map result = DataProxy.queryForMap(serviceName, operationName, params);
         System.out.println(result.size());*/
    }

    @Test
    public void testRestUerProfile()
    {
        String serviceName = "UserProfileService";
        String operationName = "DataQuery";
        Map params = new HashMap();
        List tagContents = new ArrayList();
        tagContents.add("QIANBAO_AUTH_STATUS");
        params.put("uid","3004975915");
        params.put("tagNames",tagContents);

        String urlPrefix = "http://ws.userprofile.infosec.ctripcorp.com/userprofilews";
        int queryTimeout = 500;
        DataProxyRequest request = new DataProxyRequest();
        request.setServiceName(serviceName);
        request.setOperationName(operationName);
        request.setParams(params);
        String responseTxt = null;
        try
        {
            responseTxt = Request.Post(urlPrefix + "/rest/dataproxy/query")
                    .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(queryTimeout)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
        DataProxyResponse response = Utils.JSON.parseObject(responseTxt, DataProxyResponse.class);

        Map newResult = null;
        if (request.getServiceName().equals("UserProfileService")) {
            newResult = parseProfileResult(response.getResult());
        } else {
            newResult = response.getResult();
        }
        System.out.println(JSON.toJSONString(newResult));
    }

    private static Map parseProfileResult(Map result) {
        if (result != null) {
            if (result.get("tagName") != null) {
                return parseResult(result);
            } else if (result.get("tagNames") != null) {
                Object tagValues = result.get("tagNames");
                List oldResults = Utils.JSON.parseObject(Utils.JSON.toJSONString(tagValues), List.class);
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
            List tagContent = oldValue.get("tagContent") == null ? new ArrayList() : Utils.JSON.parseObject(Utils.JSON.toJSONString(oldValue.get("tagContent")), List.class);
            newResult.put(tagName, tagContent);
        }
        return newResult;
    }

    public Map getNewResult(Map oldValue) {
        Map newResult = new HashMap();
        String tagDataType = oldValue.get("tagDataType") == null ? "" : oldValue.get("tagDataType").toString();
        if (tagDataType.toLowerCase().equals("int") || tagDataType.toLowerCase().equals("string") || tagDataType.toLowerCase().equals("datetime")
                || tagDataType.toLowerCase().equals("boolean")) {
            String tagName = oldValue.get("tagName") == null ? "" : oldValue.get("tagName").toString();
            String tagContent = oldValue.get("tagContent") == null ? "" : oldValue.get("tagContent").toString();
            newResult.put(tagName, tagContent);
        } else if (tagDataType.toLowerCase().equals("list")) {
            String tagName = oldValue.get("tagName") == null ? "" : oldValue.get("tagName").toString();
            List tagContent = oldValue.get("tagContent") == null ? new ArrayList() : (List) oldValue.get("tagContent");
            newResult.put(tagName, tagContent);
        }
        return newResult;
    }
}
