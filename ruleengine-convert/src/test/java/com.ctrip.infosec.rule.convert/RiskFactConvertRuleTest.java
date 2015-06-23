package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Caches;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.convert.config.InternalConvertConfigHolder;
import com.ctrip.infosec.rule.convert.internal.DataUnit;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.List;
import java.util.Map;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine.xml"})
public class RiskFactConvertRuleTest {


    @Test
    public void testApply() throws Exception {
        RiskFact riskFact = new RiskFact();
        riskFact.setEventId("11");
        riskFact.setEventPoint("CP0007012");
        riskFact.setAppId("11");

//        map.put("DealInfo", ImmutableMap.of("ReqID",7888,"CheckStatus",0));

        String factTxt = "{\n" +
                "    \"b\": \"b\",\n" +
                "    \"o\": {\n" +
                "        \"b\": \"o_b\",\n" +
                "        \"o\": {\n" +
                "            \"b\": \"o_o_b\"\n" +
                "        },\n" +
                "        \"l\": [\n" +
                "            {\n" +
                "                \"b\": \"First_o_l_b\",\n" +
                "                \"o\": {\n" +
                "                    \"b\": \"First_o_l_o_b\"\n" +
                "                }\n" +
                "            },\n" +
                "            {\n" +
                "                \"b\": \"second_o_l_b\",\n" +
                "                \"o\": {\n" +
                "                    \"b\": \"seconde_o_l_o_b\"\n" +
                "                }\n" +
                "            }\n" +
                "        ]\n" +
                "    },\n" +
                "    \"l\": [\n" +
                "        {\n" +
                "            \"b\": \"First_o_l_b\",\n" +
                "            \"o\": {\n" +
                "                \"b\": \"First_o_l_o_b\"\n" +
                "            }\n" +
                "        },\n" +
                "        {\n" +
                "            \"b\": \"second_o_l_b\",\n" +
                "            \"o\": {\n" +
                "                \"b\": \"seconde_o_l_o_b\"\n" +
                "            }\n" +
                "        }\n" +
                "    ]\n" +
                "}";


        Map map = JSON.parseObject(factTxt, Map.class);
        riskFact.setEventBody(map);
        RiskFactConvertRule riskFactConvertRule = new RiskFactConvertRule();
        InternalRiskFact apply = riskFactConvertRule.apply(riskFact);
            List<DataUnit> dataUnits = apply.getDataUnits();
        /**
         * 将获取的results结果输入格式化如：
         *
         {
         "md2" : {
         "List" : [ {
         "basicType" : "First_o_l_o_b",
         "basicType1" : "First_o_l_b"
         }, {
         "basicType" : "seconde_o_l_o_b",
         "basicType1" : "second_o_l_b"
         } ],
         "Obj" : {
         "basicType" : [ "First_o_l_o_b", "seconde_o_l_o_b" ]
         },
         "basicType" : [ "First_o_l_o_b", "seconde_o_l_o_b" ],
         "md3" : {
         "list" : [ {
         "basicType" : "First_o_l_b",
         "basicType1" : "First_o_l_o_b"
         }, {
         "basicType" : "second_o_l_b",
         "basicType1" : "seconde_o_l_o_b"
         } ],
         "obj" : {
         "basicType" : [ "First_o_l_o_b", "seconde_o_l_o_b" ]
         }
         }
         }
         }
         *
         */
            System.out.println("------------------format print----------------------");
            for(DataUnit dataUnit:dataUnits) {
                    System.out.println(Utils.JSON.toPrettyJSONString(dataUnit.getData()));
            }
            System.out.println("-----------------format print end-----------------------");

    }


}