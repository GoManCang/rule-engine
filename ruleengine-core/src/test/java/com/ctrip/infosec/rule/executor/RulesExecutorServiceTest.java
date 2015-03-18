/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import org.junit.Test;
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
public class RulesExecutorServiceTest {

    @Autowired
    RulesExecutorService rulesExecutorService;

    @Test
    public void testExecuteSyncRules() {
        System.out.println("executeSyncRules");
        String factTxt = "{\n"
                + "    \"eventPoint\": \"CP0011004\",\n"
                + "    \"eventId\": \"dfsfsdfsdfsd\",\n"
                + "    \"appId\": null,\n"
                + "    \"eventBody\": {\n"
                + "        \"actualAmount\": 650,\n"
                + "        \"amount\": 6500,\n"
                + "        \"bizType\": \"11\",\n"
                + "        \"bookingDate\": \"/Date(1422385584947+0800)/\",\n"
                + "        \"contactInfo\": \"{\\\"Name\\\":\\\"携程客户\\\",\\\"Tel\\\":\\\"\\\",\\\"Mobile\\\":\\\"013980868606\\\",\\\"Email\\\":\\\"\\\",\\\"Fax\\\":\\\"\\\",\\\"ConfirmType\\\":\\\"CSM\\\"}\",\n"
                + "        \"currency\": \"RMB\",\n"
                + "        \"firstDepartureTime\": \"/Date(1422577500000+0800)/\",\n"
                + "        \"isHide\": false,\n"
                + "        \"isPartial\": \"\",\n"
                + "        \"itemInfos\": [\n"
                + "            {\n"
                + "                \"ArrivalTime\": \"/Date(1422586200000+0800)/\",\n"
                + "                \"Description\": \"商旅三方协议客户不适用，限邮寄行程单及成都市区送取、机场取票。\",\n"
                + "                \"FlightNo\": \"EU2217\",\n"
                + "                \"FlightWay\": \"S\",\n"
                + "                \"FromAddress\": \"CTU\",\n"
                + "                \"FromCityId\": \"28\",\n"
                + "                \"FromCityName\": \"成都\",\n"
                + "                \"IsSurface\": \"F\",\n"
                + "                \"OrderCategory\": \"Flight\",\n"
                + "                \"Price\": 570,\n"
                + "                \"SubClass\": \"V\",\n"
                + "                \"TakeOffTime\": \"/Date(1422577500000+0800)/\",\n"
                + "                \"ToAddress\": \"SZX\",\n"
                + "                \"ToCityId\": \"30\",\n"
                + "                \"ToCityName\": \"深圳\"\n"
                + "            }\n"
                + "        ],\n"
                + "        \"message_CreateTime\": \"2015-1-28 3:06:25\",\n"
                + "        \"operateTime\": \"/Date(1422385584973+0800)/\",\n"
                + "        \"operators\": \"\",\n"
                + "        \"OrderDescription\": \"未提交\",\n"
                + "        \"orderId\": 1212830376,\n"
                + "        \"orderStatus\": \"FLIGHT_UNCOMMIT\",\n"
                + "        \"orderType\": \"国内\",\n"
                + "        \"passengers\": [\n"
                + "            {\n"
                + "                \"AgeType\": \"ADU\",\n"
                + "                \"BirthDate\": \"1979-9-19 0:00:00\",\n"
                + "                \"CardNo\": \"510221197909190614\",\n"
                + "                \"CardType\": \"1\",\n"
                + "                \"Gender\": \"M\",\n"
                + "                \"Name\": \"朱诚\"\n"
                + "            }\n"
                + "        ],\n"
                + "        \"remarks\": \"\",\n"
                + "        \"serverFrom\": \"client/android/sanxing\",\n"
                + "        \"sourceFromCode\": \"APP\",\n"
                + "        \"specialPriceType\": \"SR\",\n"
                + "        \"ticketStatus\": \"A\",\n"
                + "        \"uid\": \"_zx514906000183\",\n"
                + "        \"version\": \"0:0\"\n"
                + "    },\n"
                + "    \"results\": {\n"
                + "        \"testUserProfileWrite\": {\n"
                + "            \"time\": \"10\",\n"
                + "            \"riskLevel\": \"10\",\n"
                + "            \"riskMessage\": \"dfs\"\n"
                + "        }\n"
                + "    },\n"
                + "    \"finalResult\": {},\n"
                + "    \"ext\": {\n"
                + "        \"CHANNEL\": \"CMessage\",\n"
                + "        \"descTimestamp\": 2645479504140\n"
                + "    },\n"
                + "    \"requestReceive\": \"2015-03-04 00:34:55.860\"\n"
                + "}";
        RiskFact fact = JSON.parseObject(factTxt, RiskFact.class);
        fact = rulesExecutorService.executeSyncRules(fact);
        System.out.println("results: " + JSON.toPrettyJSONString(fact.results));
    }

    @Test
    public void testExecuteAsyncRules() {
        System.out.println("executeAsyncRules");
        String factTxt = "{\n"
                + "    \"eventPoint\": \"CP0011004\",\n"
                + "    \"eventId\": \"dfsfsdfsdfsd\",\n"
                + "    \"appId\": null,\n"
                + "    \"eventBody\": {\n"
                + "        \"actualAmount\": 650,\n"
                + "        \"amount\": 6500,\n"
                + "        \"bizType\": \"11\",\n"
                + "        \"bookingDate\": \"/Date(1422385584947+0800)/\",\n"
                + "        \"contactInfo\": \"{\\\"Name\\\":\\\"携程客户\\\",\\\"Tel\\\":\\\"\\\",\\\"Mobile\\\":\\\"013980868606\\\",\\\"Email\\\":\\\"\\\",\\\"Fax\\\":\\\"\\\",\\\"ConfirmType\\\":\\\"CSM\\\"}\",\n"
                + "        \"currency\": \"RMB\",\n"
                + "        \"firstDepartureTime\": \"/Date(1422577500000+0800)/\",\n"
                + "        \"isHide\": false,\n"
                + "        \"isPartial\": \"\",\n"
                + "        \"itemInfos\": [\n"
                + "            {\n"
                + "                \"ArrivalTime\": \"/Date(1422586200000+0800)/\",\n"
                + "                \"Description\": \"商旅三方协议客户不适用，限邮寄行程单及成都市区送取、机场取票。\",\n"
                + "                \"FlightNo\": \"EU2217\",\n"
                + "                \"FlightWay\": \"S\",\n"
                + "                \"FromAddress\": \"CTU\",\n"
                + "                \"FromCityId\": \"28\",\n"
                + "                \"FromCityName\": \"成都\",\n"
                + "                \"IsSurface\": \"F\",\n"
                + "                \"OrderCategory\": \"Flight\",\n"
                + "                \"Price\": 570,\n"
                + "                \"SubClass\": \"V\",\n"
                + "                \"TakeOffTime\": \"/Date(1422577500000+0800)/\",\n"
                + "                \"ToAddress\": \"SZX\",\n"
                + "                \"ToCityId\": \"30\",\n"
                + "                \"ToCityName\": \"深圳\"\n"
                + "            }\n"
                + "        ],\n"
                + "        \"message_CreateTime\": \"2015-1-28 3:06:25\",\n"
                + "        \"operateTime\": \"/Date(1422385584973+0800)/\",\n"
                + "        \"operators\": \"\",\n"
                + "        \"OrderDescription\": \"未提交\",\n"
                + "        \"orderId\": 1212830376,\n"
                + "        \"orderStatus\": \"FLIGHT_UNCOMMIT\",\n"
                + "        \"orderType\": \"国内\",\n"
                + "        \"passengers\": [\n"
                + "            {\n"
                + "                \"AgeType\": \"ADU\",\n"
                + "                \"BirthDate\": \"1979-9-19 0:00:00\",\n"
                + "                \"CardNo\": \"510221197909190614\",\n"
                + "                \"CardType\": \"1\",\n"
                + "                \"Gender\": \"M\",\n"
                + "                \"Name\": \"朱诚\"\n"
                + "            }\n"
                + "        ],\n"
                + "        \"remarks\": \"\",\n"
                + "        \"serverFrom\": \"client/android/sanxing\",\n"
                + "        \"sourceFromCode\": \"APP\",\n"
                + "        \"specialPriceType\": \"SR\",\n"
                + "        \"ticketStatus\": \"A\",\n"
                + "        \"uid\": \"_zx514906000183\",\n"
                + "        \"version\": \"0:0\"\n"
                + "    },\n"
                + "    \"results\": {\n"
                + "        \"testUserProfileWrite\": {\n"
                + "            \"time\": \"10\",\n"
                + "            \"riskLevel\": \"10\",\n"
                + "            \"riskMessage\": \"dfs\"\n"
                + "        }\n"
                + "    },\n"
                + "    \"finalResult\": {},\n"
                + "    \"ext\": {\n"
                + "        \"CHANNEL\": \"CMessage\",\n"
                + "        \"descTimestamp\": 2645479504140\n"
                + "    },\n"
                + "    \"requestReceive\": \"2015-03-04 00:34:55.860\"\n"
                + "}";
        RiskFact fact = JSON.parseObject(factTxt, RiskFact.class);
        fact = rulesExecutorService.executeAsyncRules(fact);
        System.out.println("results: " + JSON.toPrettyJSONString(fact.results));
    }

}
