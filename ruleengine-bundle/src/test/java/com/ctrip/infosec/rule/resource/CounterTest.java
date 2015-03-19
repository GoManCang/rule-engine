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
import java.util.Map;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author zhengby
 */
public class CounterTest {

    @Test
    public void testPush() {
        System.out.println("push");
        String bizNo = "0003";
        Map<String, Object> kvData = JSON.parseObject("{\"uid\":\"123456\",\"userIp\":\"8.8.8.8\",\"orderId\":\"A124\",\"mobilePhone\":\"13888888888\",\"orderDate\":\"2015-03-15 16:20:03\"}", Map.class);
        FlowPushResponse result = Counter.push(bizNo, kvData);
        assertEquals("0", result.getErrorCode());
    }

    @Test
    public void testQueryFlowData() {
        System.out.println("queryFlowData");
        String flowNo = "F0003001";
        String fieldName = "同一IP对应的预定量";
        FlowAccuracy accuracy = FlowAccuracy.EveryMin;
        String timeWindow = "0,-1439";
        Map<String, Object> kvData = JSON.parseObject("{\"uid\":\"123456\",\"userIp\":\"8.8.8.8\",\"orderId\":\"A124\",\"mobilePhone\":\"13888888888\",\"orderDate\":\"2015-03-15 16:20:03\"}", Map.class);
        FlowQueryResponse result = Counter.queryFlowData(flowNo, fieldName, accuracy, timeWindow, kvData);
        assertEquals("0", result.getErrorCode());

        System.out.println("flowData: " + result.getFlowData().longValue());
    }
}
