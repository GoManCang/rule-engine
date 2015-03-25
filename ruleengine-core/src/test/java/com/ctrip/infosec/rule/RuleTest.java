/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.counter.model.PolicyExecuteResponse;
import com.ctrip.infosec.counter.model.PolicyExecuteResult;
import com.ctrip.infosec.rule.resource.Counter;
import static com.ctrip.infosec.rule.util.Emitter.emit;
import com.google.common.collect.ImmutableMap;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine*.xml"})
public class RuleTest {

    @Test
    public void testCP0006021() {
        System.out.println("CP0006021");
        for (int i = 0; i < 11; i++) {
            System.out.println("exec R1: " + i);
            R1();
        }
    }

    void R1() {
        RiskFact $fact = new RiskFact();
        $fact.eventPoint = "CP0006021";
        $fact.ext.put(Constants.key_ruleNo, "CP0006021001");

        $fact.eventBody.put("appID", 1000111);
        $fact.eventBody.put("couponCode", "CCODE111");
        $fact.eventBody.put("couponID", "CID111");
        $fact.eventBody.put("userID", "U111");

        String appId = "" + $fact.eventBody.get("appID");
        String couponCode = "" + $fact.eventBody.get("couponCode");
        String couponId = "" + $fact.eventBody.get("couponID");
        String uid = "" + $fact.eventBody.get("userID");
        
        $fact.results.clear();

        //push to countServer
        Map kvData = ImmutableMap.of("appId", appId, "couponCode", couponCode, "couponId", couponId, "uid", uid);
        PolicyExecuteResponse response = Counter.execute("P0006021001", kvData);
        if ("0".equals(response.getErrorCode())) {
            PolicyExecuteResult policyExecuteResult = response.getPolicyExecuteResult();
            String resultCode = policyExecuteResult.getResultCode();
            String resultMessage = policyExecuteResult.getResultMessage();
            if (!"000".equals(resultCode)) {
                emit($fact, resultCode, resultMessage);
                System.out.println("results: " + JSON.toPrettyJSONString($fact.results));
            }
        }

        //push to countServer
        Counter.push("0006", kvData);
    }
}
