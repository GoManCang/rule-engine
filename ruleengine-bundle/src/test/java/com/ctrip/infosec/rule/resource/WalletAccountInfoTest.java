package com.ctrip.infosec.rule.resource;

import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

/**
 * Created by lpxie on 2015/8/26.
 */
public class WalletAccountInfoTest {
    @Test
    public void test()
    {
        Map result = WalletAccountInfo.query("wwwwww");
        Assert.assertNotNull(result);
    }
}
