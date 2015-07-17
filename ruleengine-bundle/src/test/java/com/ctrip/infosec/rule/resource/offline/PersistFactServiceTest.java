package com.ctrip.infosec.rule.resource.offline;

import com.ctrip.infosec.common.model.RiskFact;
import com.meidusa.fastjson.JSON;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Created by yxjiang on 2015/7/17.
 */
public class PersistFactServiceTest {
    @Test
    @Ignore
    public void testSave(){
        String fact = "{\n" +
                "  \"eventPoint\": \"CP0033001\",\n" +
                "  \"requestTime\": \"2015-07-07 15:45:47.819\",\n" +
                "  \"appId\": \"670205\",\n" +
                "  \"eventBody\": {\n" +
                "    \"orderid\": 9045094,\n" +
                "    \"merchantid\": \"124\",\n" +
                "    \"checktype\": 2,\n" +
                "    \"referenceno\": \"123\",\n" +
                "    \"paymentinfos\": [\n" +
                "      {\n" +
                "        \"prepaytype\": \"CCARD\",\n" +
                "        \"amount\": 10.0,\n" +
                "        \"refno\": 123,\n" +
                "        \"cardinfoid\": 0,\n" +
                "        \"creditcardinfo\": {\n" +
                "          \"cardinfoid\": 28996388,\n" +
                "          \"creditcardtype\": 11,\n" +
                "          \"infoid\": 123,\n" +
                "          \"cvaliditycode\": \"456558858\",\n" +
                "          \"ccardnocode\": \"789\",\n" +
                "          \"cardholder\": \"刘刘\",\n" +
                "          \"cardbin\": \"12355858\",\n" +
                "          \"ccardlastnocode\": \"56652588\",\n" +
                "          \"ccardprenocode\": \"123255858\",\n" +
                "          \"statename\": \"1235588\",\n" +
                "          \"billingaddress\": \"5532558\",\n" +
                "          \"nationality\": \"85535588\",\n" +
                "          \"nationalityofisuue\": \"123558\",\n" +
                "          \"bankofcardissue\": \"123558852\",\n" +
                "          \"isforigencard\": \"T\"\n" +
                "        }\n" +
                "      },\n" +
                "      {\n" +
                "        \"prepaytype\": \"Tmony\",\n" +
                "        \"amount\": 1.0,\n" +
                "        \"refno\": 789,\n" +
                "        \"cardinfoid\": 0,\n" +
                "        \"creditcardinfo\": {\n" +
                "          \"cardinfoid\": 28900008,\n" +
                "          \"creditcardtype\": 2,\n" +
                "          \"infoid\": 456,\n" +
                "          \"cvaliditycode\": \"77777 \",\n" +
                "          \"ccardnocode\": \"41111\",\n" +
                "          \"cardholder\": \"33333\",\n" +
                "          \"cardbin\": \"666666\",\n" +
                "          \"ccardlastnocode\": \"4444\",\n" +
                "          \"ccardprenocode\": \"444444\",\n" +
                "          \"statename\": \"77777\",\n" +
                "          \"billingaddress\": \"9999\",\n" +
                "          \"nationality\": \"12222\",\n" +
                "          \"nationalityofisuue\": \"6666\",\n" +
                "          \"bankofcardissue\": \"4444\",\n" +
                "          \"isforigencard\": \"T\"\n" +
                "        }\n" +
                "      }\n" +
                "    ],\n" +
                "    \"latitude\": 0.0,\n" +
                "    \"longitude\": 0.0,\n" +
                "    \"paymethod\": \"1\",\n" +
                "    \"payvalidationmethod\": \"1\",\n" +
                "    \"bankvalidationmethod\": \" 2\",\n" +
                "    \"validationfailsreason\": \" 3\",\n" +
                "    \"clientos\": \" 5\",\n" +
                "    \"clientidorip\": \"6\",\n" +
                "    \"deducttype\": \"1\",\n" +
                "    \"ordertype\": 14\n" +
                "  }\n" +
                "}\n";
        new PersistFactService("http://10.2.56.170:8080/flowtable4j/rest/saveData4Offline").saveFact(JSON.parseObject(fact, RiskFact.class));
    }
}