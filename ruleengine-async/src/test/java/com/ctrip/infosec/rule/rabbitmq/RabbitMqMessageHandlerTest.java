package com.ctrip.infosec.rule.rabbitmq;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

import static org.junit.Assert.*;

/**
 * Created by yxjiang on 2015/7/7.
 */
@ContextConfiguration("classpath*:spring/ruleengine*.xml")
public class RabbitMqMessageHandlerTest extends AbstractJUnit4SpringContextTests {
    @Autowired
    RabbitMqMessageHandler handler;

    @Test
    public void testHandleMessage() throws Exception {
        String msg = IOUtils.toString(getClass().getClassLoader().getResourceAsStream("CP0001002.json"), "utf-8");
        handler.handleMessage(msg);
    }
}