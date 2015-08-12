package com.ctrip.infosec.rule.resource;

import com.meidusa.fastjson.JSON;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by lpxie on 15-8-12.
 */
public class CheckBWGListTest {

    @Test
    public void testQueryBWGList() {
        Map params = new HashMap();
        params.put("uid", "test12345678");
        List result = BWListRuleEngine.check(params);
        System.out.println("result: " + JSON.toJSONString(result));
    }
}
