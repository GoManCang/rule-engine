package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.common.model.RiskFact;
import org.dom4j.DocumentException;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by lpxie on 15-3-23.
 */
public class CardInTest
{
    @Test
    public void testQueryCardInfo()
    {
        //cardInfoId为30075005这个的可以查询到数据，留这备用
        RiskFact fact = ReadFactFile.getFact("searchCardInfo.json");
        Map params = new HashMap();
        params.put("cardInfoId", fact.eventBody.get("CardInfoID")+"");
        try
        {
            Map map = CardInfo.query("getinfo",params);
            Assert.assertNotNull(map);
            Assert.assertTrue(map.size()>0);
        } catch (DocumentException e)
        {
            e.printStackTrace();
        }
    }
}
