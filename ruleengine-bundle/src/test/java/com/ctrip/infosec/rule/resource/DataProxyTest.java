/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.model.DataProxyResponse;
import com.google.common.collect.ImmutableMap;

import java.util.*;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author zhengby
 */
public class DataProxyTest {

    /**
     * 根据ip地址获取相关的信息
     */
    @Test
    public void testQuery() {
        /*System.out.println("query");
        String serviceName = "IpService";
        String operationName = "getIpArea";
        Map params = ImmutableMap.of("ip", "202.96.209.133");
        DataProxyResponse result = DataProxy.query(serviceName, operationName, params);
        assertEquals(0, result.getRtnCode());
        System.out.println("result: " + JSON.toJSONString(result.getResult()));*/

        /*String serviceName1 = "MobilePhoneService";
        String operationName1 = "getMobileArea";
        Map params1 = ImmutableMap.of("mobileNumber", "13917863756");
        DataProxyResponse result1 = DataProxy.query(serviceName1, operationName1, params1);
        System.out.println("result1: " + JSON.toJSONString(result1.getResult()));*/

       /* String serviceName = "CRMService";
        String operationName = "getMemberInfo";
        Map params = ImmutableMap.of("uid", "wwwwww");
        DataProxyResponse result = DataProxy.query(serviceName, operationName, params);

        Map result1 = result.getResult();*/

        /*String serviceName = "AirPortService";
        String operationName = "getAirPortCity";
        Map params = ImmutableMap.of("airport", "PEK");
        DataProxyResponse result = DataProxy.query(serviceName, operationName, params);
        Map result1 = result.getResult();*/

        String serviceName = "UserProfileService";
        String operationName = "DataQuery";
        List tagContents = new ArrayList();
        tagContents.add("RECENT_IP");
        tagContents.add("RECENT_IPAREA");
        Map params = ImmutableMap.of("uid", "M00713231","tagNames",tagContents);
        DataProxyResponse result = DataProxy.query(serviceName, operationName, params);
        Map result1 = result.getResult();
        //change data form
        //数据类型：int string boolean  list  datetime
        //tagNames的情况
        List<Map> oldResults = (List<Map>)result1.get("tagNames");
        List<Map> newResults = new ArrayList<Map>();
        Iterator iterator = oldResults.iterator();
        while(iterator.hasNext())
        {
            Map oneResult = (Map)iterator.next();
            newResults.add(getNewResult(oneResult));
        }
        Map finalResult = new HashMap();
        finalResult.put("result",newResults);
        result.setResult(finalResult);

        /*String serviceName = "UserProfileService";
        String operationName = "DataQuery";
        //http://userprofile.infosec.ctripcorp.com/userprofileweb/;jsessionid=11099F242AD077BD1F8A53F60FA6E68B
        Map params = ImmutableMap.of("uid", "M00713231","tagName","RECENT_IP");//STATUS  RECENT_IP
        DataProxyResponse result = DataProxy.query(serviceName, operationName, params);
        Map result1 = result.getResult();
        //change data form
        //数据类型：int string boolean  list  datetime
        //tagName的情况
        Map newResult = getNewResult(result1);
        System.out.println(newResult.size());*/

        /*Map params = new HashMap();
        params.put("cardInfoId", "30075005");
        Map map = CardInfo.query("getinfo", params);
        System.out.println(map.size());*/
    }

    public Map getNewResult(Map oldValue)
    {
        Map newResult = new HashMap();
        String tagDataType = oldValue.get("tagDataType") == null ? "" : oldValue.get("tagDataType").toString();
        if(tagDataType.toLowerCase().equals("int") || tagDataType.toLowerCase().equals("string") || tagDataType.toLowerCase().equals("datetime")
                || tagDataType.toLowerCase().equals("boolean"))
        {
            String tagName = oldValue.get("tagName") == null ? "" : oldValue.get("tagName").toString();
            String tagContent = oldValue.get("tagContent") == null ? "" : oldValue.get("tagContent").toString();
            newResult.put(tagName,tagContent);
        }else if(tagDataType.toLowerCase().equals("list"))
        {
            String tagName = oldValue.get("tagName") == null ? "" : oldValue.get("tagName").toString();
            List tagContent = oldValue.get("tagContent") == null ? new ArrayList() : (List)oldValue.get("tagContent");
            newResult.put(tagName,tagContent);
        }
        return newResult;
    }
}
