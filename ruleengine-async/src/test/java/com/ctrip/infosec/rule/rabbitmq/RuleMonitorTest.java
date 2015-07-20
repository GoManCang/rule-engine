/**
 * 
 */
package com.ctrip.infosec.rule.rabbitmq;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ctrip.infosec.configs.rule.monitor.RuleMonitorRepository;

/**
 *
 * @author sjchi
 * @date 2015年5月12日 下午1:10:24
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine-test.xml"})
public class RuleMonitorTest {
	
	@Test
	@Ignore
	public void test1() throws InterruptedException{
		
		int n = 1000;
		while(n > 0){
			
			RuleMonitorRepository.increaseCounter("cp0001","CP0001002_2offline");
//			repository.increaseCounter("PayAdapter001");
			
			n--;
		}
		
		
		Thread.sleep(60000);
		
		
	}
	

}
