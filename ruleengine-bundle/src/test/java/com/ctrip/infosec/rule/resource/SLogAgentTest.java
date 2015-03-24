package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.common.model.RiskFact;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

/**
 * Created by lpxie on 15-3-24.
 */
public class SLogAgentTest
{
    @Test
    public void testChangeDataForm()
    {
        RiskFact fact = ReadFactFile.getFact("searchCardInfo.json");
        Map map = SlogAgent.changeDataForm(fact);
//        Assert.assertNotNull(map);
        Assert.assertTrue(map.size()>0);
    }

    @Test
    public void testSendToSLog()
    {
        RiskFact fact = ReadFactFile.getFact("searchCardInfo.json");
        Map map = SlogAgent.changeDataForm(fact);
    }
}
