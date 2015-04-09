package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.common.model.RiskFact;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by lpxie on 15-4-9.
 */
public class CustomerInfoTest
{
    @Test
    public void testQueryCustomerInfo() {
        //uid为000这个的可以查询到数据，留这备用
        RiskFact fact = ReadFactFile.getFact("searchCardInfo.json");
        Map params = new HashMap();
        params.put("uid", fact.eventBody.get("uid") + "");

        Map map = CustomerInfo.query(params);
        Assert.assertNotNull(map);
        Assert.assertTrue(map.size() > 0);
    }
}
