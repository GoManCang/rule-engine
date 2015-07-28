/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.counter.enums.FlowAccuracy;
import com.ctrip.infosec.counter.model.FlowPushResponse;
import com.ctrip.infosec.counter.model.FlowQueryResponse;
import com.ctrip.infosec.counter.model.GetDataFieldListResponse;
import com.google.common.collect.Lists;
import java.util.Map;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
//@Ignore
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class CounterTest {

    @Test
    public void testFieldList() {
        System.out.println("datafieldList");
        String bizNo = "0003";
        GetDataFieldListResponse result = Counter.datafieldList(bizNo);
        assertEquals("0", result.getErrorCode());
        System.out.println("datafieldList: " + JSON.toPrettyJSONString(result));
    }

    @Test
    public void testPush() {
        System.out.println("push");
        String bizNo = "0003";
        Map<String, String> kvData = JSON.parseObject("{\"uid\":\"123456\",\"userIp\":\"8.8.8.8\",\"orderId\":\"A124\",\"mobilePhone\":\"13888888888\",\"orderDate\":\"2015-03-15 16:20:03\"}", Map.class);
        FlowPushResponse result = Counter.push(bizNo, kvData);
        assertEquals("0", result.getErrorCode());

        result = Counter.pushToFlow(bizNo, Lists.newArrayList("F0003001","F0003002","F0003003"), kvData);
        assertEquals("0", result.getErrorCode());
    }

    @Test
    public void testQueryFlowData() {
        System.out.println("queryFlowData");
        String flowNo = "F0003001";
        String fieldName = "同一IP对应的预定量";
        FlowAccuracy accuracy = FlowAccuracy.EveryMin;
        String timeWindow = "0,-1439";
        Map<String, String> kvData = JSON.parseObject("{\"uid\":\"123456\",\"userIp\":\"8.8.8.8\",\"orderId\":\"A124\",\"mobilePhone\":\"13888888888\",\"orderDate\":\"2015-03-15 16:20:03\"}", Map.class);
        FlowQueryResponse result = Counter.queryFlowData(flowNo, fieldName, accuracy, timeWindow, kvData);
        assertEquals("0", result.getErrorCode());

        System.out.println("flowData: " + result.getFlowData().longValue());
    }
}
