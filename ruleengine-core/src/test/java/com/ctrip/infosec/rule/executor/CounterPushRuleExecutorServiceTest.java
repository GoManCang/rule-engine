package com.ctrip.infosec.rule.executor;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.utils.Utils;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine*.xml"})
public class CounterPushRuleExecutorServiceTest {
	
	@Autowired
	CounterPushRulesExecutorService service;
	
	ResourceLoader resourceLoader = new DefaultResourceLoader();
	
	@Test
	public void test1() throws IOException{
		
		Resource resource = resourceLoader.getResource("/CounterPush.json");
		
		String data = IOUtils.toString(resource.getInputStream());
		
		RiskFact fact = Utils.JSON.parseObject(data, RiskFact.class);
		
		service.executeCounterPushRules(fact, false);
		
	}

}
