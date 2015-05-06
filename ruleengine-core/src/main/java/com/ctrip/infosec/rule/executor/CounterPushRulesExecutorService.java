package com.ctrip.infosec.rule.executor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.CounterPushRule;
import com.ctrip.infosec.configs.utils.EventBodyUtils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.Counter;
import com.meidusa.fastjson.JSON;

/**
 *
 * @author sjchi
 * @date 2015年5月6日 下午3:16:01
 */
@Service
public class CounterPushRulesExecutorService {
	
	private static final Logger logger = LoggerFactory.getLogger(CounterPushRulesExecutorService.class);
	
	public RiskFact executeCounterPushRules(RiskFact fact,boolean isAsync){
		execute(fact, false);
		return fact;
	}
	
	
	private void execute(RiskFact fact, boolean isAsync) {
		
		// matchRules      
        List<CounterPushRule> matchedRules = Configs.matchCounterPushRules(fact);
        logger.info(Contexts.getLogPrefix() + "matched CounterPushRules: " + matchedRules.size());

        StopWatch clock = new StopWatch();
        try {
            clock.reset();
            clock.start();
            
            for(CounterPushRule rule : matchedRules){
            	executeInternal(fact,rule);
            }

            clock.stop();
            long handlingTime = clock.getTime();
            if (handlingTime > 50) {
                logger.info(Contexts.getLogPrefix() + "CounterPushRuleExecutorService#execute: eventPoint: " + fact.getEventPoint() + ", usage: " + handlingTime + "ms");
            }

        } catch (Throwable ex) {
            logger.warn(Contexts.getLogPrefix() + "invoke CounterPushRuleExecutorService#execute failed. eventpoint: " + fact.getEventPoint(), ex);
        }
		
	}
	
	/**
	 * 根据规则来组装需要推送的dataMap,然后执行Counter#push
	 * @param rule
	 * @param fact
	 */
	private void executeInternal(RiskFact fact,CounterPushRule rule){
		
		Map<String, String> dataMap = new HashMap<String, String>();
		
		Map<String, String> fieldMap = rule.getFieldMap();
		for(Entry<String,String> entry : fieldMap.entrySet()){
			
			//从fact.eventBody中取出需要映射的值放入需要推送的dataMap中
			//支持value多层嵌套关系
			String data = EventBodyUtils.valueAsString(fact.getEventBody(), entry.getValue());
			if(!StringUtils.isEmpty(data)){
				dataMap.put(entry.getKey(),data);
			}
		}
		
		if(dataMap.size() > 0){
			
			Counter.push(rule.getBizNo(), dataMap);
			
			logger.info(Contexts.getLogPrefix() + "Counter push: bizNo-->" + rule.getBizNo() +",eventPoint-->" + rule.getEventPoint() + ",dataMap-->" + JSON.toJSONString(dataMap));
		}else{
			logger.warn(Contexts.getLogPrefix() + "Counter push: bizNo-->" + rule.getBizNo() +",eventPoint-->" + rule.getEventPoint() + ",dataMap is empty");
		}
	}

}
