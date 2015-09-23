package com.ctrip.infosec.rule.resource;

import com.meidusa.fastjson.JSON;
import java.util.Map;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Created by lpxie on 15-9-6.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class TongDunTest {

    @Test
//    @Ignore
    public void test() {
        String ip = "8.8.8.8";
        String mobile = "18740223918";
        Map score = TongDun.queryTradeEvent(ip, mobile);
        Map score1 = TongDun.queryRegEvent(ip, mobile);
        System.out.println(score + "------" + JSON.toJSONString(score));
        System.out.println(score1 + "------" + JSON.toJSONString(score1));
    }
}
