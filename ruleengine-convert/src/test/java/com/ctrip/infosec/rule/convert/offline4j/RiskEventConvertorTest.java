package com.ctrip.infosec.rule.convert.offline4j;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.event.DataUnitDefinition;
import com.ctrip.infosec.configs.event.DataUnitMetadata;
import com.ctrip.infosec.configs.event.HeaderMappingBizType;
import com.ctrip.infosec.configs.utils.EventBodyUtils;
import com.ctrip.infosec.rule.convert.internal.DataUnit;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.google.common.collect.Lists;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine.xml"})
public class RiskEventConvertorTest {
	
	@Autowired
	private RiskEventConvertor riskEventConvertor;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@Test
	public void testConvert() {
		
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


        Map eventBody = JSON.parseObject(factTxt, Map.class);
        System.out.println("EventBodyUtils.valueAsString = " + EventBodyUtils.valueAsString(eventBody, "CrmMemberInfo.bindedMobilePhone"));
		
		RiskFact riskFact = new RiskFact();
		riskFact.setAppId("test appid");
		riskFact.setEventId("test eventId");
		riskFact.setEventPoint("CP0001008");
		riskFact.setEventBody(eventBody);
		
		InternalRiskFact internalRiskFact = new InternalRiskFact();
		internalRiskFact.setAppId("test internal app id");
		internalRiskFact.setEventId("test internal event id");
		internalRiskFact.setEventPoint("CP0001008");
		internalRiskFact.setReqId(123l);
		
		List<DataUnit> dataUnits = Lists.newArrayList();
		DataUnit dataUnit = new DataUnit();
		dataUnit.setData(eventBody);
		DataUnitDefinition dataUnitDefinition = new DataUnitDefinition();
		DataUnitMetadata dataUnitMetadata = new DataUnitMetadata();
		dataUnitMetadata.setName("metaName");
		dataUnitDefinition.setMetadata(dataUnitMetadata);
		dataUnit.setDefinition(dataUnitDefinition);
		dataUnits.add(dataUnit);
		internalRiskFact.setDataUnits(dataUnits);
		//internalRiskFact.setDataUnits(new ArrayList<DataUnit>());
		
		Object eventObject = null;
		try {
			eventObject = riskEventConvertor.convert(internalRiskFact, riskFact, HeaderMappingBizType.Offline4J);
			System.out.println(eventObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
