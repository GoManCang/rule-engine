package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.action.FrozenAccount;
import com.meidusa.fastjson.JSON;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

/**
 * Created by lpxie on 15-4-14.
 */
public class FrozenAccountTest {
    @Test
    public void testFrozenOrNot() {

        Map result1 = FrozenAccount.frozen("E181160046", "冻结解冻账户", "zhengby");
        System.out.print("result1: " + JSON.toJSONString(result1));
        Assert.assertNotNull(result1);

        /*Map result2 = FrozenAccount.unfrozen("test", "冻结解冻账户", "zhengby");
        System.out.print("result2: " + JSON.toJSONString(result2));*/

    }
}
