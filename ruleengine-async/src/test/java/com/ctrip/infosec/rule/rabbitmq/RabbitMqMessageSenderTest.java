/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import java.io.IOException;
import java.nio.charset.Charset;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.annotation.Resource;

/**
 *
 * @author zhengby
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine-test.xml"})
public class RabbitMqMessageSenderTest {

    @Resource(name="ruleEngineTemplate")
    private AmqpTemplate ruleEngineTemplate;

    @Test
    public void testSend() throws IOException {
        System.out.println("send");
        RiskFact fact = ReadFactFile.getFact("cp0027004.json");
        byte[] b = JSON.toJSONString(fact).getBytes(Charset.forName("UTF-8"));
        for (int i = 0; i < 100000; i++) {
            ruleEngineTemplate.convertAndSend("ruleengine", b);
            System.out.println("发送了  "+i);
        }

    }

}
