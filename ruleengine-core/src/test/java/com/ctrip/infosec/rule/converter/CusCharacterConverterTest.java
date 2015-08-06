/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.utils.EventBodyUtils;
import com.google.common.collect.ImmutableMap;


/**
 *
 * @author sjchi
 * @date 2015年8月6日 下午4:49:01
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class CusCharacterConverterTest {

    
    @Test
    public void testConvert() throws Exception{
    	
    	UserProfileTagsConverter converter = new UserProfileTagsConverter();
    	
    	RiskFact fact = new RiskFact();
    	fact.eventBody.put("uid", "wwwwww");
    	
    	converter.convert(PreActionEnums.UserProfileTags, ImmutableMap.of("uid", "uid","tags","CUSCHARACTER,RECENT_IP"),fact, "userInfo");
//    	Assert.assertTrue(StringUtils.isNotBlank(EventBodyUtils.valueAsString(fact.eventBody, "userInfo.CUSCHARACTER")));
    	
    	RiskFact fact1 = new RiskFact();
    	fact1.eventBody.put("uid", "wwwwww");
    	converter.convert(PreActionEnums.UserProfileTags, ImmutableMap.of("uid", "uid","tags","CUSCHARACTER"),fact1, "userInfo");
//    	Assert.assertTrue(StringUtils.isNotBlank(EventBodyUtils.valueAsString(fact.eventBody, "userInfo.CUSCHARACTER")));
    	
    	RiskFact fact2 = new RiskFact();
    	fact2.eventBody.put("uid", "wwwwww");
    	converter.convert(PreActionEnums.UserProfileTags, ImmutableMap.of("uid", "uid","tags","CUSCHARACTER,ABC"),fact2, "userInfo");
//    	Assert.assertTrue(StringUtils.isNotBlank(EventBodyUtils.valueAsString(fact.eventBody, "userInfo.CUSCHARACTER")));
    	System.out.println();
    }
    
    
    

}
