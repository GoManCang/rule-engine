package com.ctrip.infosec.rule.rabbitmq;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

import java.nio.charset.Charset;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ctrip.infosec.common.model.RiskFact;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine-test.xml"})
public class Offline4jMessageHandlerTest {
	
	@Autowired
	private OfflineMessageSender sender;

	@Test
	public void test(){
		
		System.out.println("send");
        RiskFact fact = ReadFactFile.getFact("cp0027004.json");
        byte[] b = JSON.toJSONString(fact).getBytes(Charset.forName("UTF-8"));
        for (int i = 0; i < 2; i++) {
        	sender.sendToOffline(fact);
            System.out.println("发送了  " + i);
        }
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
		
	}
	
}
