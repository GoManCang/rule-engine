package com.ctrip.infosec.rule.resource;

import com.meidusa.fastjson.JSON;
import org.junit.Test;

import java.util.Map;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Created by lpxie on 2015/8/19.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class QiAnTest {

    @Test
//    @Ignore
    public void test() {
        Map result = QiAn.queryRegEvent("8.8.8.8", "18022729102");
        System.out.println(JSON.toJSONString(result));
    }
}
