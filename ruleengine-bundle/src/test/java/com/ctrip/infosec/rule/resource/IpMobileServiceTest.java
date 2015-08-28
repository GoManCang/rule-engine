package com.ctrip.infosec.rule.resource;

import com.meidusa.fastjson.JSON;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.Iterator;
import java.util.Map;

/**
 * Created by lpxie on 2015/8/19.
 */
public class IpMobileServiceTest {
    @Test
    public void test()
    {

        Map result = IpMobileService.query("8.8.8.8", "18022729102");
        System.out.println(JSON.toJSONString(result));
    }
}
