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

<<<<<<< HEAD
        Map result = FrozenAccount.frozenOrNot(params);
        Assert.assertNotNull(result);

        /*params.put("operStatus","F"); //T=冻解 F=解冻
        Map result1 = FrozenAccount.frozenOrNot(params);
        Assert.assertNotNull(result1);*/
=======
    @Test
    public void testFrozenOrNot() {

        Map result1 = FrozenAccount.frozen("test", "冻结解冻账户", "zhengby");
        System.out.print("result1: " + JSON.toJSONString(result1));
        Assert.assertNotNull(result1);

        Map result2 = FrozenAccount.unfrozen("test", "冻结解冻账户", "zhengby");
        System.out.print("result2: " + JSON.toJSONString(result2));
>>>>>>> 62a332b6d96629c6a2c558e59c117c78191c42d2
    }
}
