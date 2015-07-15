/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.venus;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ctrip.infosec.common.model.RiskFact;
import com.meidusa.fastjson.JSON;
import org.junit.Ignore;

/**
 *
 * @author zhengby
 */
//@Ignore
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine-venus-test.xml"})
public class RuleEngineRemoteServiceTest {

    @Autowired
    RuleEngineRemoteService ruleEngineRemoteService;

    @Test
//    @Ignore
    public void testVerify() throws IOException {

//    	Resource resource = new DefaultResourceLoader().getResource("/fact.txt");
//    	String factStr = IOUtils.toString(resource.getInputStream());
//    	RiskFact fact = JSON.parseObject(factStr,RiskFact.class);
        System.out.println("verify");
        RiskFact fact = JSON.parseObject("{\"eventPoint\":\"CP0011001\",\"eventId\":\"055bab40-2b06-11e5-a07b-ad65b5f4ddc1\",\"appId\":\"670203\",\"eventBody\":{\"aAirPort\":\"PEK\",\"aCity\":1,\"agencyName\":\"上海百益航空服务有限公司\",\"agencyid\":1009,\"amount\":920.0,\"cValidityCode\":\"\",\"cardInfoID\":0,\"checkType\":1,\"contactEMail\":\"\",\"contactName\":\"张蕊\",\"contactTel\":\"\",\"corporationID\":\"\",\"creditCardType\":0,\"dAirPort\":\"KWL\",\"dCity\":33,\"eAirPort\":\"KWL\",\"experience\":8263,\"flightClass\":\"N\",\"flightCost\":920.0,\"flightCostRate\":1.0,\"flightprice\":920.0,\"fltRiskLevel\":0,\"forignMobilePhone\":\"\",\"infoID\":0,\"insuranceCost\":0.0,\"insurance_fee\":0.0,\"isClient\":\"\",\"isForeignCard\":\"\",\"isGuarantee\":\"\",\"isNeedCheckRisk\":\"\",\"isOnline\":\"F\",\"isTempUser\":\"F\",\"isUidHasBlackCard\":\"\",\"latitude\":0.0,\"longitude\":0.0,\"mD5Password\":\"\",\"mobilePhone\":\"13803145369\",\"nationality\":\"\",\"nationalityofisuue\":\"\",\"needCheckBlackList\":\"T\",\"orderDate\":\"2015-07-15 23:27:36.319\",\"orderID\":1393384852,\"orderType\":1,\"packageAttachFee\":0.0,\"passengerInfoList\":[{\"passengerAgeType\":\"CHI\",\"passengerBirthday\":\"2009-01-19 00:00:00.000\",\"passengerCardIDType\":\"2\",\"passengerCardNo\":\"E33262070\",\"passengerCardNoType\":\"\",\"passengerGender\":\"U\",\"passengerName\":\"李佳一\",\"passengerNationality\":\"\"}],\"paymentInfos\":[],\"persons\":1,\"postAddress\":\"\",\"prepayType\":\"\",\"realReservationType\":0,\"referenceNo\":0,\"reservationType\":0,\"riskCountrolDeadline\":\"0001-01-01 00:00:00.000\",\"salesType\":2,\"segmentInfoList\":[{\"aAirPort\":\"PEK\",\"arrivaltime\":\"2015-07-19 21:10:00.000\",\"dAirPort\":\"KWL\",\"pataResult\":0,\"seatClass\":\"Y\",\"sequence\":1,\"subClass\":\"Y\",\"takeofftime\":\"2015-07-19 18:15:00.000\",\"vehicleType\":0}],\"sendTickerAddr\":\"\",\"serverfrom\":\"fltint.sh.ctriptravel.com\",\"signUpDate\":\"2013-02-06 19:12:52.000\",\"subOrderType\":0,\"takeOffTime\":\"2015-07-19 18:15:00.000\",\"targetOrder\":0,\"tot_Oilfee\":0.0,\"tot_Tax\":0.0,\"totalDiscountAmount\":0.0,\"totalPenalty\":0.0,\"uid\":\"13803145369\",\"urgencyLevel\":2,\"userIP\":\"10.251.19.181\",\"vipGrade\":20},\"ext\":{\"CHANNEL\":\"EXECUTE\",\"descTimestamp\":2633905943564,\"reqId\":\"863256849\"},\"requestTime\":\"2015-07-15 23:27:36.429\",\"requestReceive\":\"2015-07-15 23:27:36.436\"}", RiskFact.class);

        fact = ruleEngineRemoteService.verify(fact);
        System.out.println("fact: " + JSON.toJSONString(fact));
    }

}
