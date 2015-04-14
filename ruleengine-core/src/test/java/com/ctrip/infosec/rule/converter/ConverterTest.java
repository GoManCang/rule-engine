/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import com.google.common.collect.ImmutableMap;
import com.meidusa.fastjson.JSON;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine*.xml"})
public class ConverterTest {

    @Autowired
    private ConverterLocator converterLocator;

    /**
     * Test of convert method, of class Converter.
     */
    @Test
    public void testConvert() throws Exception {
        System.out.println("convert");
        Converter converter = converterLocator.getConverter(PreActionEnums.Ip2ProvinceCity);
        RiskFact fact = new RiskFact();
        fact.eventBody.put("userIp", "202.96.209.133");
        converter.convert(PreActionEnums.Ip2ProvinceCity, ImmutableMap.of("ip", "userIp"), fact, null);

        System.out.println("convert: " + JSON.toJSONString(fact));
        
        converter = converterLocator.getConverter(PreActionEnums.Mobile2ProvinceCity);
        fact = new RiskFact();
        fact.eventBody.put("mobile", "13917863756");
        converter.convert(PreActionEnums.Mobile2ProvinceCity, ImmutableMap.of("mobile", "mobile"), fact, null);

        System.out.println("convert: " + JSON.toJSONString(fact));
    }

}
