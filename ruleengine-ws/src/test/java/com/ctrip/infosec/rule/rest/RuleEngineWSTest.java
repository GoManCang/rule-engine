package com.ctrip.infosec.rule.rest;

import com.ctrip.infosec.common.model.RiskFact;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.entity.StringEntity;
import org.junit.Test;

import static com.ctrip.infosec.configs.utils.Utils.JSON;
import org.junit.Ignore;

/**
 * Created by lpxie on 15-3-25.
 */
public class RuleEngineWSTest {

    @Test
    @Ignore
    public void sentDataToRuleEngineWS() {
        //规则引擎的同步服务地址
        String fatUrl = "http://10.2.10.77:8080/ruleenginews/rule/query";

        for (int i = 0; i < 10; i++) {
            try {
                String str = IOUtils.toString(ReadFactFile.class.getClassLoader().getResourceAsStream("TestFact.json"), "utf-8");
                Response resultFact = Request.Post(fatUrl).body(new StringEntity(str)).connectTimeout(5000).socketTimeout(1000).execute();
                RiskFact fact = JSON.parseObject(resultFact.returnContent().asString(), RiskFact.class);
                System.out.println(i + "\n" + fact.finalResult.toString());
            } catch (Exception exp) {

            }

        }
    }
}
