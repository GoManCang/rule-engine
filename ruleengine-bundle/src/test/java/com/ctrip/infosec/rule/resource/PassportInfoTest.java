package com.ctrip.infosec.rule.resource;

import com.ctrip.sec.userprofile.client.service.PassportService;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.List;

/**
 * Created by lpxie on 15-6-3.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class PassportInfoTest
{
    @Test
    public void testGetPassportInfo() throws InterruptedException
    {
        //PassportService.setConfigUrl("http://ws.userprofile.infosec.fat70.qa.nt.ctripcorp.com:8080/userprofilews");
        //Thread.sleep(30000);
        String passport = "12733100";
        List<String> results = PassportInfo.getCountriesByPassportNum(passport);
        Assert.assertNotNull(results);
    }
}
