/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.model.DataProxyResponse;
import com.google.common.collect.ImmutableMap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

        /*String serviceName = "UserProfileService";
        String operationName = "DataQuery";

        List tagContents = new ArrayList();
        tagContents.add("RECENT_IP");
        tagContents.add("RECENT_IPAREA");
        Map params = ImmutableMap.of("uid", "M00713231","tagNames",tagContents);
        DataProxyResponse result = DataProxy.query(serviceName, operationName, params);
        Map result1 = result.getResult();*/

        Map params = new HashMap();
        params.put("cardInfoId", "30075005");
        Map map = CardInfo.query("getinfo", params);
        System.out.println(map.size());
    }
}
