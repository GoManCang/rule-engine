package com.ctrip.infosec.rule.resource;

import org.junit.Test;

import java.util.Map;

/**
 * Created by lpxie on 2015/8/19.
 */
public class IpMobileServiceTest {
    @Test
    public void test()
    {
        Map result = IpMobileService.query("8.8.8.8","18022729102");
    }
}
