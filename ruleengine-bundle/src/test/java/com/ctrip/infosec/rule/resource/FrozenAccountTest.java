package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.action.FrozenAccount;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by lpxie on 15-4-14.
 */
public class FrozenAccountTest
{
    @Test
    public void testFrozenOrNot()
    {
        Map params = new HashMap();
        params.put("uid","test");
        params.put("operStatus","T"); //T=冻解 F=解冻
        params.put("oper","");
        params.put("remark","冻结解冻账户");

        /*Map result = FrozenAccount.frozenOrNot(params);
        Assert.assertNotNull(result);*/

        params.put("operStatus","F"); //T=冻解 F=解冻
        Map result1 = FrozenAccount.frozenOrNot(params);
        Assert.assertNotNull(result1);
    }
}
