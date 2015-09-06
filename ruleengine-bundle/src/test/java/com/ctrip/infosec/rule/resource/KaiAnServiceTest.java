package com.ctrip.infosec.rule.resource;

import com.meidusa.fastjson.JSON;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Map;

/**
 * Created by lpxie on 2015/8/19.
 */
public class KaiAnServiceTest {
    @Test
    @Ignore
    public void test()
    {
        Map result = KaiAnService.query("8.8.8.8", "18022729102");
        System.out.println(JSON.toJSONString(result));
    }
}
