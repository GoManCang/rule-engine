package com.ctrip.infosec.rule.resource;

import org.junit.Ignore;
import org.junit.Test;

/**
 * Created by lpxie on 15-9-6.
 */
public class TongDunServiceTest {
    @Test
    @Ignore
    public void test()
    {
        String ip = "8.8.8.8";
        String mobile = "18740223918";
        String score = TongDunService.queryT(ip,mobile);
        String score1 = TongDunService.queryR(ip,mobile);
        System.out.println(score+"------"+score1);
    }
}
