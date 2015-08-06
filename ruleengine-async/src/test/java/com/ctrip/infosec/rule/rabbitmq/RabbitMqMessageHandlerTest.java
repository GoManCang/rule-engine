package com.ctrip.infosec.rule.rabbitmq;

import org.apache.commons.io.IOUtils;
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
        String msg = IOUtils.toString(getClass().getClassLoader().getResourceAsStream("CP0026001.json"), "utf-8");
        handler.handleMessage(msg);
        
        RiskFact fact = JSON.parseObject(msg, RiskFact.class);
        Long riskReqId = MapUtils.getLong(fact.ext, Constants.key_reqId);
        System.out.println("riskReqId = " + riskReqId);
    }
}