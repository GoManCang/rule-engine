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
                "    \"CrmMemberInfo\": {\n" +
                "        \"agentType\": \"  \",\n" +
                "        \"bindedMobilePhone\": \"13600971055\",\n" +
                "        \"birth\": \"1900-08-19T00:00:00\",\n" +
                "        \"city\": \"0\",\n" +
                "        \"ctripcardno\": \"3003222141\",\n" +
                "        \"experience\": \"1250\",\n" +
                "        \"gender\": \"F\",\n" +
                "        \"mD5Password\": \"28B1AC44DA9F48B6D0171861B5808FFD\",\n" +
                "        \"maxGrade\": \"30\",\n" +
                "        \"mileageIncluding\": \"HF\",\n" +
                "        \"mobilePhone\": \"           \",\n" +
                "        \"scSaleCardEmp\": \"15Mplus\",\n" +
                "        \"signupdate\": \"2012-08-30T13:43:12\",\n" +
                "        \"sourceid\": \"2\",\n" +
                "        \"uid\": \"3003222141\",\n" +
                "        \"updateTime\": \"0001-01-01T00:00:00\",\n" +
                "        \"userName\": \"刘露\",\n" +
                "        \"vip\": \"F\",\n" +
                "        \"vipGrade\": \"0\"\n" +
                "    },\n" +
                "    \"Ip2ProvinceCity\": {\n" +
                "        \"Area\": \"\",\n" +
                "        \"City\": \"\",\n" +
                "        \"CityId\": \"-999\",\n" +
                "        \"Country\": \"中国\",\n" +
                "        \"CountryId\": \"1\",\n" +
                "        \"EndAddr\": \"1971912703\",\n" +
                "        \"Latitude\": \"35\",\n" +
                "        \"Longitude\": \"105\",\n" +
                "        \"NationCode\": \"CN\",\n" +
                "        \"Province\": \"\",\n" +
                "        \"ProvinceId\": \"-999\",\n" +
                "        \"Remark\": \"城市名为空\",\n" +
                "        \"StartAddr\": \"1971860480\",\n" +
                "        \"Type_Company\": \"移动\"\n" +
                "    },\n" +
                "    \"accPayID\": \"494267\",\n" +
                "    \"bankCardNo\": \"45490204\",\n" +
                "    \"bankCardType\": \"0\",\n" +
                "    \"cardBankId\": \"0\",\n" +
                "    \"checkType\": \"1\",\n" +
                "    \"clientID\": \"12001104710002341646\",\n" +
                "    \"clientVersion\": \"6.5\",\n" +
                "    \"currency\": \"1\",\n" +
                "    \"deriveInfo\": {\n" +
                "        \"idProvince\": \"河南\",\n" +
                "        \"isNetworkip\": \"T\"\n" +
                "    },\n" +
                "    \"finalResultGroupByScene\": {},\n" +
                "    \"idNo\": \"412828198808195467\",\n" +
                "    \"idType\": \"1\",\n" +
                "    \"ipInfo\": {\n" +
                "        \"Area\": \"\",\n" +
                "        \"City\": \"\",\n" +
                "        \"CityId\": \"-999\",\n" +
                "        \"Country\": \"中国\",\n" +
                "        \"CountryId\": \"1\",\n" +
                "        \"EndAddr\": \"1971912703\",\n" +
                "        \"Latitude\": \"35\",\n" +
                "        \"Longitude\": \"105\",\n" +
                "        \"NationCode\": \"CN\",\n" +
                "        \"Province\": \"\",\n" +
                "        \"ProvinceId\": \"-999\",\n" +
                "        \"Remark\": \"城市名为空\",\n" +
                "        \"StartAddr\": \"1971860480\",\n" +
                "        \"Type_Company\": \"移动\"\n" +
                "    },\n" +
                "    \"latitude\": \"24.47054\",\n" +
                "    \"longitude\": \"118.0934\",\n" +
                "    \"merchantID\": \"200086\",\n" +
                "    \"merchantOrderID\": \"19090457\",\n" +
                "    \"orderAmount\": \"30\",\n" +
                "    \"orderDate\": \"2015-06-18 15:07:02.889\",\n" +
                "    \"orderID\": \"19090457\",\n" +
                "    \"orderType\": \"28\",\n" +
                "    \"paymentInfos\": [],\n" +
                "    \"postActions\": {},\n" +
                "    \"serverfrom\": \"APP\",\n" +
                "    \"subOrderType\": \"5\",\n" +
                "    \"uid\": \"3003222141\",\n" +
                "    \"userIP\": \"117.136.75.60\",\n" +
                "    \"withdrawType\": \"1\",\n" +
                "    \"infoSW\": {\n" +
                "      \"WC\":3333333" +
                "},"+
                "    \"infoSWList\": [\n" +
                "        {\n" +
                "            \"entry\": \"1\",\n" +"\"bcn\":\"AAA\""+
                "        },\n" +
                "        {\n" +
                "            \"entry\": \"2\",\n" +"\"bcn\":\"BBB\"" +
                "        },\n" +
                "        {\n" +
                "            \"entry\": \"3\",\n" +"\"bcn\":\"CCC\""+
                "        }\n" +
                "    ],"+
                "    \"test\": [\n" +
                "        {\n" +
                "            \"entry\": \"1\",\n" +"\"bcn\":\"AAA\""+
                "        },\n" +
                "        {\n" +
                "            \n" +"\"bcn\":\"BBB\"" +
                "        },\n" +
                "        {\n" +
                "            \"entry\": \"3\",\n" +"\"bcn\":\"CCC\""+
                "        }\n" +
                "    ],"+
                "  \"listmd\": {\n" +
                "        \"list1\": [\n" +
                "            {\n" +
                "                \"name\": \"listName1\",\n" +
                "                \"age\": 1" +
                "            },\n" +
                "            {\n" +
                "                \"name\": \"listName2\",\n" +
                "                \"age\": 2" +
                "            }\n" +
                "        ]\n" +
                "    }"+
                "}";


        Map map = JSON.parseObject(factTxt, Map.class);
        riskFact.setEventBody(map);
        RiskFactConvertRule riskFactConvertRule = new RiskFactConvertRule();
        InternalRiskFact apply = riskFactConvertRule.apply(riskFact);
            List<DataUnit> dataUnits = apply.getDataUnits();

            System.out.println("------------------format print----------------------");
            for(DataUnit dataUnit:dataUnits) {
                    System.out.println(Utils.JSON.toPrettyJSONString(dataUnit.getData()));
            }
            System.out.println("-----------------format print end-----------------------");

    }


}