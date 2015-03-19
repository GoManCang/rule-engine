/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.model.DataProxyResponse;
import com.google.common.collect.ImmutableMap;
import java.util.Map;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author zhengby
 */
public class DataProxyTest {

    @Test
    public void testQuery() {
        System.out.println("query");
        String serviceName = "IpService";
        String operationName = "getIpArea";
        Map params = ImmutableMap.of("ip", "202.96.209.133");
        DataProxyResponse result = DataProxy.query(serviceName, operationName, params);
        assertEquals(0, result.getRtnCode());
        System.out.println("result: " + JSON.toJSONString(result.getResult()));
    }

}
