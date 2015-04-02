/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.venus;

import com.ctrip.infosec.common.model.RiskFact;
import com.meidusa.fastjson.JSON;
import org.junit.Test;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
//@Ignore
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine-venus-test.xml"})
public class RuleEngineRemoteServiceTest {

    @Autowired
    RuleEngineRemoteService ruleEngineRemoteService;

    @Test
    public void testVerify() {
        System.out.println("verify");
        RiskFact fact = JSON.parseObject("{\n"
                + "  \"eventPoint\" : \"CP0006021\",\n"
                + "  \"eventBody\" : {\n"
                + "    \"couponCode\" : \"hfqxxwnqva\",\n"
                + "    \"userID\" : \"66932736\"\n"
                + "  },\n"
                + "  \"requestTime\" : \"2015-04-01 08:43:01.148\"\n"
                + "}", RiskFact.class);

        fact = ruleEngineRemoteService.verify(fact);
        System.out.println("fact: " + JSON.toJSONString(fact));
    }

}
