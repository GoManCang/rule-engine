package com.ctrip.infosec.rule.resource;

import org.junit.Test;

import java.util.Map;

/**
 * Created by lpxie on 2015/8/24.
 */
public class GiftCardBalanceTest {
    @Test
    public void testIfGet()
    {
        Map result = GiftCardBalance.query("www");
        System.out.println("TotalAvailableAmount:"+result.get("TotalAvailableAmount")+"\t"+"TotalUnAvailableAmount:"+result.get("TotalUnAvailableAmount"));

        return;
    }
}
