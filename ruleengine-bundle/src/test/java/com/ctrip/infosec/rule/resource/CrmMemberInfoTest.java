package com.ctrip.infosec.rule.resource;

import com.meidusa.fastjson.JSON;
import org.junit.Test;

import java.util.Map;

/**
 * Created by lpxie on 15-4-9.
 */
public class CrmMemberInfoTest {

    @Test
    public void testQueryCrmMemberInfo() {

        Map map = CrmMemberInfo.queryByUid("test111111");
        System.out.println("result: " + JSON.toJSONString(map));
    }
}
