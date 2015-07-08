/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.event.PreRule;
import com.meidusa.fastjson.JSON;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine*.xml"})
public class PreRulesExecutorServiceTest {

    @Autowired
    PreRulesExecutorService preRulesExecutorService;

    /**
     * Test of executePreRules method, of class PreRulesExecutorService.
     */
    @Test
    public void testExecutePreRules() {
        System.out.println("executePreRules");
        RiskFact fact = JSON.parseObject("{\n"
                + "    \"eventPoint\": \"CP0001002\",\n"
                + "    \"eventBody\": {\n"
                + "        \"UserProfileInfo\": {\n"
                + "            \"CUSCHARACTER\": \"NEW\"\n"
                + "        },\n"
                + "        \"bankValidationMethod\": \" 2\",\n"
                + "        \"businessItem\": \"\",\n"
                + "        \"checkType\": \"2\",\n"
                + "        \"clientIDOrIP\": \"6\",\n"
                + "        \"clientOS\": \" 5\",\n"
                + "        \"contactEMail\": \"LXY@163.COM\",\n"
                + "        \"deductType\": \"1\",\n"
                + "        \"isNetworkIp\": \"F\",\n"
                + "        \"isNormalMobilePhone\": \"T\",\n"
                + "        \"latitude\": \"0\",\n"
                + "        \"longitude\": \"0\",\n"
                + "        \"merchantID\": \"124\",\n"
                + "        \"mobilePhone\": \"15161121660\",\n"
                + "        \"mobilePhoneDomain\": \"1516112\",\n"
                + "        \"orderAmount\": \"0\",\n"
                + "        \"orderDate\": \"0001-01-01 00:00:00.000\",\n"
                + "        \"orderID\": \"9045103\",\n"
                + "        \"orderPrepayType\": \"CCARD\",\n"
                + "        \"orderType\": \"14\",\n"
                + "        \"payMethod\": \"1\",\n"
                + "        \"payValidationMethod\": \"1\",\n"
                + "        \"paymentInfos\": [\n"
                + "            {\n"
                + "                \"amount\": 10,\n"
                + "                \"cardInfoID\": 28996388,\n"
                + "                \"creditCardInfo\": {\n"
                + "                    \"bankOfCardIssue\": \"123558852\",\n"
                + "                    \"billingAddress\": \"5532558\",\n"
                + "                    \"cCardLastNoCode\": \"56652588\",\n"
                + "                    \"cCardNoCode\": \"789\",\n"
                + "                    \"cCardPreNoCode\": \"123255858\",\n"
                + "                    \"cValidityCode\": \"456558858\",\n"
                + "                    \"cardBin\": \"12355858\",\n"
                + "                    \"cardHolder\": \"刘刘\",\n"
                + "                    \"cardInfoID\": 28996388,\n"
                + "                    \"creditCardType\": 11,\n"
                + "                    \"infoID\": 123,\n"
                + "                    \"isForigenCard\": \"T\",\n"
                + "                    \"nationality\": \"85535588\",\n"
                + "                    \"nationalityofisuue\": \"123558\",\n"
                + "                    \"stateName\": \"1235588\"\n"
                + "                },\n"
                + "                \"prepayType\": \"CCARD\",\n"
                + "                \"refNo\": 123\n"
                + "            },\n"
                + "            {\n"
                + "                \"amount\": 1,\n"
                + "                \"cardInfoID\": 28900008,\n"
                + "                \"creditCardInfo\": {\n"
                + "                    \"bankOfCardIssue\": \"4444\",\n"
                + "                    \"billingAddress\": \"9999\",\n"
                + "                    \"cCardLastNoCode\": \"4444\",\n"
                + "                    \"cCardNoCode\": \"41111\",\n"
                + "                    \"cCardPreNoCode\": \"444444\",\n"
                + "                    \"cValidityCode\": \"77777 \",\n"
                + "                    \"cardBin\": \"666666\",\n"
                + "                    \"cardHolder\": \"33333\",\n"
                + "                    \"cardInfoID\": 28900008,\n"
                + "                    \"creditCardType\": 2,\n"
                + "                    \"infoID\": 456,\n"
                + "                    \"isForigenCard\": \"T\",\n"
                + "                    \"nationality\": \"12222\",\n"
                + "                    \"nationalityofisuue\": \"6666\",\n"
                + "                    \"stateName\": \"77777\"\n"
                + "                },\n"
                + "                \"prepayType\": \"Tmony\",\n"
                + "                \"refNo\": 789\n"
                + "            }\n"
                + "        ],\n"
                + "        \"postActions\": {},\n"
                + "        \"productID\": \"0\",\n"
                + "        \"quantity\": \"0\",\n"
                + "        \"referenceNo\": \"123\",\n"
                + "        \"saleBeginTime\": \"0001-01-01 00:00:00.000\",\n"
                + "        \"saleEndTime\": \"0001-01-01 00:00:00.000\",\n"
                + "        \"uid\": \"D00026295\",\n"
                + "        \"userIP\": \"127.0.0.1\",\n"
                + "        \"validationFailsReason\": \" 3\"\n"
                + "    },\n"
                + "    \"requestTime\": \"2015-07-07 18:01:22.183\"\n"
                + "}", RiskFact.class);
        boolean isAsync = false;

        RiskFact result = preRulesExecutorService.executePreRules(fact, isAsync);

    }

}
