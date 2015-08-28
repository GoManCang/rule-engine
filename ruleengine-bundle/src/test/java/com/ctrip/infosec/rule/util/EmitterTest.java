/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.util;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.counter.model.CounterRuleExecuteResult;
import com.ctrip.infosec.counter.model.PolicyExecuteResult;
import java.util.List;
import java.util.Map;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author zhengby
 */
public class EmitterTest {

    /**
     * Test of emitBWListResults method, of class Emitter.
     */
    @Test
    public void testEmitBWListResults() {
        System.out.println("emitBWListResults");
        RiskFact fact = Utils.JSON.parseObject("{\"eventPoint\":\"CP0012101\",\"eventId\":\"d9aa0fd0-4d58-11e5-b3a8-5f475aeafb8c\",\"appId\":\"670203\",\"eventBody\":{\"businessItem\":\"\",\"canAccountPay\":\"bbb\",\"checkType\":1,\"companyType\":\"T\",\"contactEMail\":\"lxyy@163.com\",\"contactName\":\"ContactName\",\"contactTel\":\"8117755\",\"corp_PayType\":\"abc\",\"corporationID\":\"12558\",\"isOnline\":\"T\",\"latitude\":0.0,\"longitude\":0.0,\"merchantID\":\"1558\",\"merchantOrderID\":\"9874386\",\"mobilePhone\":\"15161121660\",\"orderAmount\":1225.0,\"orderDate\":\"2014-08-11 11:22:05.094\",\"orderID\":0,\"orderPrepayType\":\"\",\"orderType\":18,\"paymentInfos\":[],\"referenceNo\":\"12255\",\"sendTickerAddr\":\"SendTickerAddr\",\"serverfrom\":\"Serverfrom\",\"subOrderType\":0,\"tieYouOrderInfos\":[{\"acity\":\"常州\",\"dcity\":\"常州\",\"departureDate\":\"2014-08-11 11:22:05.096\",\"fromStationName\":\"FromStationName\",\"insuranceType\":\"33\",\"passengerIDCode\":\"66\",\"passengerIDType\":\"22\",\"passengerName\":\"PassengerName1\",\"seatClass\":\"40\",\"trainNo\":\"11\"},{\"acity\":\"10\",\"dcity\":\"20\",\"departureDate\":\"2014-08-11 11:22:05.096\",\"fromStationName\":\"FromStationName2\",\"insuranceType\":\"44\",\"passengerIDCode\":\"33\",\"passengerIDType\":\"66\",\"passengerName\":\"88\",\"seatClass\":\"77\",\"trainNo\":\"22\"}],\"uid\":\"test111111\",\"userIP\":\"61.175.232.0\"},\"ext\":{\"CHANNEL\":\"EXECUTE\",\"descTimestamp\":2630132029107,\"reqId\":\"10843580\",\"_isAsync\":false},\"requestTime\":\"2015-08-28 15:46:10.835\",\"requestReceive\":\"2015-08-28 15:46:10.893\"}", RiskFact.class);
        List<Map<String, String>> bwlistResults = Utils.JSON.parseObject("[{\"ruleType\":\"ACCOUNT\",\"ruleID\":0,\"ruleName\":\"PAYMENT-CONF-LIPIN\",\"riskLevel\":278,\"ruleRemark\":\"\"},{\"ruleType\":\"ACCOUNT\",\"ruleID\":0,\"ruleName\":\"PAYMENT-CONF-CC\",\"riskLevel\":278,\"ruleRemark\":\"\"},{\"ruleType\":\"ACCOUNT\",\"ruleID\":0,\"ruleName\":\"PAYMENT-CONF-CTRIPAY\",\"riskLevel\":10,\"ruleRemark\":\"\"},{\"ruleType\":\"BW\",\"ruleID\":47312,\"ruleName\":null,\"riskLevel\":7,\"ruleRemark\":\"\"},{\"ruleType\":\"BW\",\"ruleID\":47211,\"ruleName\":null,\"riskLevel\":9,\"ruleRemark\":\"\"},{\"ruleType\":\"BW\",\"ruleID\":46912,\"ruleName\":null,\"riskLevel\":1,\"ruleRemark\":\"自动化测试使用，请勿删除！\"},{\"ruleType\":\"BW\",\"ruleID\":47310,\"ruleName\":null,\"riskLevel\":5,\"ruleRemark\":\"\"},{\"ruleType\":\"BW\",\"ruleID\":47313,\"ruleName\":null,\"riskLevel\":7,\"ruleRemark\":\"\"},{\"ruleType\":\"BW\",\"ruleID\":47184,\"ruleName\":null,\"riskLevel\":50,\"ruleRemark\":\"\"},{\"ruleType\":\"BW\",\"ruleID\":46385,\"ruleName\":null,\"riskLevel\":12,\"ruleRemark\":\"\"},{\"ruleType\":\"BW\",\"ruleID\":46640,\"ruleName\":null,\"riskLevel\":105,\"ruleRemark\":\"\"},{\"ruleType\":\"BW\",\"ruleID\":45255,\"ruleName\":null,\"riskLevel\":169,\"ruleRemark\":\"FAT和UAT同样存在，测试持续使用，请勿修改！！！\"},{\"ruleType\":\"BW\",\"ruleID\":46354,\"ruleName\":null,\"riskLevel\":66,\"ruleRemark\":\"全部类型订单测试\"},{\"ruleType\":\"BW\",\"ruleID\":47311,\"ruleName\":null,\"riskLevel\":6,\"ruleRemark\":\"\"}]", List.class);
        Emitter.emitBWListResults(fact, bwlistResults);
    }

}
