package com.ctrip.infosec.rule.resource;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.List;

/**
 * Created by lpxie on 15-7-7.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class CityToProvinceTest
{
    @Test
    public void testInt()
    {
        CityToProvince cityToProvince = new CityToProvince();
        //CityToProvince.init();
    }

    @Test
    public void testGetPro()
    {
        String single = "六安";
        String multiple = "北京";
        List singleResult = CityToProvince.getProvinceNames(single);
        List multipleResult = CityToProvince.getProvinceNames(multiple);
        System.out.println(singleResult.get(0));
        System.out.println(multipleResult.get(0)+""+multipleResult.get(1)+""+multipleResult.size());
    }
}
