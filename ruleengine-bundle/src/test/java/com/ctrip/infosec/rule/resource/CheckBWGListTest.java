package com.ctrip.infosec.rule.resource;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.rule.util.Emitter;
import com.meidusa.fastjson.JSON;

/**
 * Created by lpxie on 15-8-12.
 */
public class CheckBWGListTest {

    @Test
    @Ignore
    public void testQueryBWGList() {
        Map params = new HashMap();
        params.put("uid", "test12345678");
        List result = BWListRuleEngine.check(params);
        System.out.println("result: " + JSON.toJSONString(result));
    }
    
    @Test
    public void test2() throws IOException{
    	
    	String str = IOUtils.toString(CheckBWGListTest.class.getClassLoader().getResourceAsStream("test.json"), "utf-8");
    	
    	Map<String,String> params = (Map<String,String>)JSON.parse(str);
    	
    	List result = BWListRuleEngine.check(params);
        System.out.println("result: " + JSON.toJSONString(result));
        
        
        //适配点
        RiskFact fact = new RiskFact();
        fact.setEventPoint("CP0001001");
        Map<String,Object> map = new HashMap<String,Object>();
        map.put(Constants.key_ruleNo,"12345");
        map.put(Constants.key_isAsync,false);
        fact.setExt(map);
        Emitter.emitBWListResults(fact, result);
        System.out.println("fact: " + JSON.toJSONString(fact.getResultsGroupByScene()));
        
        //非适配点
        fact = new RiskFact();
        fact.setEventPoint("CP0001002");
        fact.getEventBody().put("orderType", "1");
        map = new HashMap<String,Object>();
        map.put(Constants.key_ruleNo,"12345");
        map.put(Constants.key_isAsync,false);
        fact.setExt(map);
        Emitter.emitBWListResults(fact, result);
        System.out.println("fact: " + JSON.toJSONString(fact.getResults()));
        
        //非适配积分点
        fact = new RiskFact();
        fact.setEventPoint("CP0001002");
        fact.getEventBody().put("orderType", "12");
        map = new HashMap<String,Object>();
        map.put(Constants.key_ruleNo,"12345");
        map.put(Constants.key_isAsync,false);
        fact.setExt(map);
        Emitter.emitBWListResults(fact, result);
        System.out.println("fact: " + JSON.toJSONString(fact.getResults()));
        
    }
}
