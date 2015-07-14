package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.utils.Utils;
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
        riskFact.setEventPoint("CP0026001");
        riskFact.setAppId("11");

//        map.put("DealInfo", ImmutableMap.of("ReqID",7888,"CheckStatus",0));
//        String factTxt="{\n" +
//                "    \"eventPoint\": \"CP0001010\",\n" +
//                "    \"mappings\": [\n" +
//                "        {\n" +
//                "            \"sourceFieldName\": \"a.b.c\",\n" +
//                "            \"targetFieldName\": \"测试metadata.test\"\n" +
//                "        },\n" +
//                "        {\n" +
//                "            \"sourceFieldName\": \"2\",\n" +
//                "            \"targetFieldName\": \"测试metadata.aaa\"\n" +
//                "        }\n" +
//                "    ],\n" +
//                "    \"updatedAt\": \"2015-06-25 18:49:05\",\n" +
//                "    \"createdAt\": \"2015-06-25 18:49:05\"\n" +
//                "}";

//        String factTxt = "{\n" +
//                "    \"b\": \"b\",\n" +
//                "    \"o\": {\n" +
//                "        \"b\": \"o_b\",\n" +
//                "        \"o\": {\n" +
//                "            \"b\": \"o_o_b\"\n" +
//                "        },\n" +
//                "        \"l\": [\n" +
//                "            {\n" +
//                "                \"b\": \"First_o_l_b\",\n" +
//                "                \"c\": \"First_o_l_c\",\n" +
//                "                \"o\": {\n" +
//                "                    \"b\": \"First_o_l_o_b\"\n" +
//                "                },\n" +
//                "\"l\":[\n" +
//                "\t\t\t\t{\t\"b\":\"1_1\"\n" +
//                ",\"c\":\"1_c_1\""+
//                "\t\t\t\t},\n" +
//                "\t\t\t\t{\n" +
//                "\t\t\t\t\"b\":\"1_2\"\n" +
//                ",\"c\":\"1_c_1\""+
//                "\t\t\t\t}\n" +
//                "\t\t\t\t]" +
//                "            },\n" +
//                "            {\n" +
//                "                \"b\": \"second_o_l_b\",\n" +
//                "                \"c\": \"second_o_l_c\",\n" +
//                "                \"o\": {\n" +
//                "                    \"b\": \"seconde_o_l_o_b\"\n" +
//                "                },\n" +
//                "\"l\":[\n" +
//                "{\"b\":\"2_1\"\n" +
//                ",\"c\":\"2_c_1\""+
//                "},\n" +
//                "{\n" +
//                "\"b\":\"2_2\"\n" +
//                ",\"c\":\"2_c_2\""+
//                "}\n" +
//                "]" +
//                "            }\n" +
//                "        ]\n" +
//                "    },\n" +
//                "    \"l\": [\n" +
//                "        {\n" +
//                "            \"b\": \"First_o_l_b\",\n" +
//                "            \"o\": {\n" +
//                "                \"b\": \"First_o_l_o_b\"\n" +
//                "            }\n" +
//                "        },\n" +
//                "        {\n" +
//                "            \"b\": \"second_o_l_b\",\n" +
//                "            \"o\": {\n" +
//                "                \"b\": \"seconde_o_l_o_b\"\n" +
//                "            }\n" +
//                "        }\n" +
//                "    ]\n" +
//                "}";

        String factTxt = " {\n" +
                "    \"UserProfileInfo\": {\n" +
                "      \"CUSCHARACTER\": \"REPEAT\"\n" +
                "    },\n" +
                "    \"aCity\": 0,\n" +
                "    \"businessItem\": \"\",\n" +
                "    \"checkType\": 1,\n" +
                "    \"contactEMail\": \"lxyy1118@163.com \",\n" +
                "    \"contactName\": \"ContactName  \",\n" +
                "    \"contactTel\": \" 8117755\",\n" +
                "    \"dCity\": 99,\n" +
                "    \"departureDate\": \"2014-06-23 11:04:18.951\",\n" +
                "    \"isOnline\": \"F\",\n" +
                "    \"latitude\": 0,\n" +
                "    \"longitude\": 0,\n" +
                "    \"merchantID\": \"MerchantID \",\n" +
                "    \"mobilePhone\": \"13701488549\",\n" +
                "    \"optionItems\": [\n" +
                "      {\n" +
                "        \"optionID\": 1,\n" +
                "        \"optionName\": \" OptionName1 \",\n" +
                "        \"optionQty\": 10\n" +
                "      },\n" +
                "      {\n" +
                "        \"optionID\": 2,\n" +
                "        \"optionName\": \" OptionName2\",\n" +
                "        \"optionQty\": 20\n" +
                "      }\n" +
                "    ],\n" +
                "    \"orderAmount\": 10,\n" +
                "    \"orderDate\": \"2014-06-23 11:04:18.951\",\n" +
                "    \"orderID\": 9077909,\n" +
                "    \"orderInfoExternalURL\": \" OrderInfoExternalURL \",\n" +
                "    \"orderPrepayType\": \"CCARD \",\n" +
                "    \"orderToSignUpDate\": 55557,\n" +
                "    \"orderType\": 22,\n" +
                "    \"paymentInfos\": [\n" +
                "      {\n" +
                "        \"amount\": 20,\n" +
                "        \"cardInfoID\": 29073076,\n" +
                "        \"creditCardInfo\": {\n" +
                "          \"bankOfCardIssue\": \"44 \",\n" +
                "          \"billingAddress\": \" 444\",\n" +
                "          \"cCardLastNoCode\": \"122358 \",\n" +
                "          \"cCardNoCode\": \"2655585\",\n" +
                "          \"cCardPreNoCode\": \" 111\",\n" +
                "          \"cValidityCode\": \"55665 \",\n" +
                "          \"cardBin\": \"5335588\",\n" +
                "          \"cardHolder\": \"晨晨\",\n" +
                "          \"cardInfoID\": 28996388,\n" +
                "          \"creditCardType\": 11,\n" +
                "          \"infoID\": 12,\n" +
                "          \"isForigenCard\": \" 44\",\n" +
                "          \"nationality\": \"4 \",\n" +
                "          \"nationalityofisuue\": \" 44\",\n" +
                "          \"stateName\": \"55555 \"\n" +
                "        },\n" +
                "        \"prepayType\": \" CCARD\",\n" +
                "        \"refNo\": 1\n" +
                "      },\n" +
                "      {\n" +
                "        \"amount\": 20,\n" +
                "        \"cardInfoID\": 28900449,\n" +
                "        \"creditCardInfo\": {\n" +
                "          \"bankOfCardIssue\": \"44 \",\n" +
                "          \"billingAddress\": \" 444\",\n" +
                "          \"cCardLastNoCode\": \"122358 \",\n" +
                "          \"cCardNoCode\": \"2655585\",\n" +
                "          \"cCardPreNoCode\": \" 111\",\n" +
                "          \"cValidityCode\": \"55665 \",\n" +
                "          \"cardBin\": \"5335588\",\n" +
                "          \"cardHolder\": \"晨晨\",\n" +
                "          \"cardInfoID\": 28900457,\n" +
                "          \"creditCardType\": 11,\n" +
                "          \"infoID\": 12,\n" +
                "          \"isForigenCard\": \" 44\",\n" +
                "          \"nationality\": \"4 \",\n" +
                "          \"nationalityofisuue\": \" 44\",\n" +
                "          \"stateName\": \"55555 \"\n" +
                "        },\n" +
                "        \"prepayType\": \" Tmony\",\n" +
                "        \"refNo\": 1\n" +
                "      }\n" +
                "    ],\n" +
                "    \"phoneProvinceName\": {\n" +
                "      \"CityName\": \"常州\",\n" +
                "      \"MobileNumber\": \"1370148\",\n" +
                "      \"MobileType\": \"江苏移动全球通卡\",\n" +
                "      \"ProvinceName\": \"江苏\"\n" +
                "    },\n" +
                "    \"productName\": \" ProductName \",\n" +
                "    \"referenceNo\": \" ReferenceNo\",\n" +
                "    \"sendTickerAddr\": \" SendTickerAddr \",\n" +
                "    \"serverfrom\": \"Serverfrom  \",\n" +
                "    \"uid\": \"test111111\",\n" +
                "    \"uidCrmMemberInfo\": {\n" +
                "      \"bindedEmail\": \"test@163.com\",\n" +
                "      \"bindedMobilePhone\": \"13616667784\",\n" +
                "      \"birth\": \"1997-01-01T00:00:00\",\n" +
                "      \"city\": \"2\",\n" +
                "      \"ctripcardno\": \"1680000044\",\n" +
                "      \"email\": \"hj_liu@ctrip.com\",\n" +
                "      \"experience\": \"-1649307515\",\n" +
                "      \"gender\": \"M\",\n" +
                "      \"mD5Password\": \"E10ADC3949BA59ABBE56E057F20F883E\",\n" +
                "      \"maxGrade\": \"10\",\n" +
                "      \"mileageIncluding\": \"HF\",\n" +
                "      \"mobilePhone\": \"13355555555\",\n" +
                "      \"scSaleCardEmp\": \"yanxie\",\n" +
                "      \"signupIP\": \"172.16.144.14\",\n" +
                "      \"signupdate\": \"2008-02-20T13:25:32\",\n" +
                "      \"sourceid\": \"8\",\n" +
                "      \"tel\": \"777777777*2222\",\n" +
                "      \"uid\": \"test111111\",\n" +
                "      \"updateTime\": \"2014-05-14T16:42:14\",\n" +
                "      \"userName\": \"test\",\n" +
                "      \"vip\": \"F\",\n" +
                "      \"vipGrade\": \"30\"\n" +
                "    },\n" +
                "    \"userIP\": \"67.20.213.60\",\n" +
                "    \"userIPCountry\": {\n" +
                "     \"Area\": \"\",\n" +
                "      \"City\": \"Buffalo\",\n" +
                "      \"CityId\": \"-999\",\n" +
                "      \"Country\": \"美国\",\n" +
                "      \"CountryId\": \"66\",\n" +
                "      \"EndAddr\": \"1125441535\",\n" +
                "      \"Latitude\": \"42.7684\",\n" +
                "      \"Longitude\": \"-78.8871\",\n" +
                "      \"NationCode\": \"US\",\n" +
                "      \"Province\": \"\",\n" +
                "      \"ProvinceId\": \"-999\",\n" +
                "      \"Remark\": \"国外数据\",\n" +
                "      \"StartAddr\": \"1125433344\",\n" +
                "      \"Type_Company\": \"State University of New Yor\"\n" +
                "    },\n" +
                "    \"userIPValue\": 1125438780,\n" +
                "    \"userInfos\": [\n" +
                "      {\n" +
                "        \"visitorCardNo\": \"VisitorCardNo1  \",\n" +
                "        \"visitorContactInfo\": \" VisitorContactInfo1 \",\n" +
                "        \"visitorName\": \"VisitorName1  \",\n" +
                "        \"visitorNationality\": \" VisitorNationality1 \"\n" +
                "      },\n" +
                "      {\n" +
                "        \"visitorCardNo\": \" VisitorCardNo2 \",\n" +
                "        \"visitorContactInfo\": \" VisitorContactInfo2 \",\n" +
                "        \"visitorName\": \" VisitorName2 \",\n" +
                "        \"visitorNationality\": \" VisitorNationality2 \"\n" +
                "      }\n" +
                "    ]\n" +
                "  }\n";

        Map map = JSON.parseObject(factTxt, Map.class);
        riskFact.setEventBody(map);
        RiskFactConvertRuleService riskFactConvertRule = new RiskFactConvertRuleService();
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
        for (DataUnit dataUnit : dataUnits) {
            System.out.println(Utils.JSON.toPrettyJSONString(dataUnit.getData()));
        }
        System.out.println("-----------------format print end-----------------------");

    }


}
