package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.common.model.RiskFact;
import org.junit.Test;

import java.util.Map;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

//@RunWith(SpringJUnit4ClassRunner.class)

public class RiskFactConvertRuleTest {


    @Test
    public void testApply() throws Exception {
        RiskFact riskFact = new RiskFact();
        riskFact.setEventId("11");
        riskFact.setEventPoint("11");
        riskFact.setAppId("11");

//        map.put("DealInfo", ImmutableMap.of("ReqID",7888,"CheckStatus",0));

        String factTxt = "{\n"
                //                + "    \"eventPoint\": \"CP0011004\",\n"
                + "    \"eventPoint\": \"CP0001002\",\n"
                + "    \"eventId\": \"99999999\",\n"
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
                + "        \"rule01\": {\n"
                + "            \"riskLevel\": 10,\n"
                + "            \"riskMessage\": \"PPPP\"\n"
                + "        },\n"
                + "        \"rule02\": {\n"
                + "            \"riskLevel\": 20,\n"
                + "            \"riskMessage\": \"DDDD\"\n"
                + "        },\n"
                + "        \"rule03\": {\n"
                + "            \"riskLevel\": 0,\n"
                + "            \"riskMessage\": \"dfFFFFs\"\n"
                + "        }\n"
                + "    },\n"
                + "    \"finalResult\": {"
                + "          \"riskLevel\": 0,\n"
                + "          \"riskMessage\": \"Pass\"\n"
                + "    },\n"
                + "    \"ext\": {\n"
                + "        \"CHANNEL\": \"CMessage\",\n"
                + "        \"descTimestamp\": 999999999999\n"
                + "    },\n"
                + "    \"requestReceive\": \"2015-03-04 00:34:55.860\"\n"
                + "}";

        Map map = JSON.parseObject(factTxt, Map.class);
        riskFact.setEventBody(map);
        RiskFactConvertRule riskFactConvertRule = new RiskFactConvertRule();
        riskFactConvertRule.apply(riskFact);
    }


}