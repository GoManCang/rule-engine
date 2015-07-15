package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.meidusa.fastjson.JSON;
import org.apache.commons.collections.MapUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;


/**
 * Created by yxjiang on 2015/7/7.
 */
@ContextConfiguration("classpath*:spring/ruleengine*.xml")
public class RabbitMqMessageHandlerTest extends AbstractJUnit4SpringContextTests {
    @Autowired
    RabbitMqMessageHandler handler;

    @Test
    public void testHandleMessage() throws Exception {
//        String msg = IOUtils.toString(getClass().getClassLoader().getResourceAsStream("CP0026001.json"), "utf-8");
        String msg = "{\"eventPoint\":\"CP0001001\",\"eventId\":\"8604da50-2acf-11e5-845c-5f475aeafb8c\",\"appId\":\"670203\",\"eventBody\":{\"DID\":\"\",\"IPAddr\":\"\",\"MerchantID\":\"123\",\"OrderID\":3770070,\"OrderType\":1,\"UID\":\"test111111\"},\"finalResult\":{\"riskLevel\":0,\"riskMessage\":\"PASS\"},\"resultsGroupByScene\":{\"data4dotnet_lxy\":{\"riskLevel\":478,\"riskMessage\":\"金额超过9.88\",\"riskScene\":[\"TMPAY\"]}},\"finalResultGroupByScene\":{\"TMPAY\":{\"riskLevel\":478,\"riskMessage\":\"金额超过9.88\"}},\"ext\":{\"CHANNEL\":\"REST\",\"SYNC_RULE_EXECUTED\":true,\"_isAsync\":false,\"_ruleNo\":\"PayAdapter001\",\"descTimestamp\":2633929350027,\"reqId\":\"8326121\"},\"requestTime\":\"2015-07-15 15:53:21.990\",\"requestReceive\":\"2015-07-15 16:57:29.973\"}";
        handler.handleMessage(msg);
        
        RiskFact fact = JSON.parseObject(msg, RiskFact.class);
        Long riskReqId = MapUtils.getLong(fact.ext, Constants.reqId);
        System.out.println("riskReqId = " + riskReqId);
    }
}