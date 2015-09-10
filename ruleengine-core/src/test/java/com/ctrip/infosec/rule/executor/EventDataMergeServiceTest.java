/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.model.RiskFact;
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
public class EventDataMergeServiceTest {

    @Autowired
    EventDataMergeService eventDataMergeService;

    @Test
    public void testExecuteRedisXXX() {
        System.out.println("executeRedisXXX");
        RiskFact fact = JSON.parseObject("{\"eventPoint\":\"CP0011001\",\"eventId\":\"5a77aa00-579a-11e5-acc0-8d456ac77926\",\"appId\":\"670203\",\"eventBody\":{\"aAirPort\":\"CGK\",\"aCity\":524,\"agencyid\":0,\"amount\":3196.0,\"cValidityCode\":\"\",\"cardInfoID\":0,\"checkType\":1,\"contactEMail\":\"test@ctrip.com\",\"contactName\":\"余女士\",\"corp_PayType\":\"OWN\",\"corporationID\":\"\",\"creditCardType\":0,\"dAirPort\":\"PEK\",\"dCity\":1,\"eAirPort\":\"XMN\",\"experience\":110465,\"flightClass\":\"I\",\"flightCost\":0.0,\"flightCostRate\":0.0,\"flightprice\":0.0,\"fltRiskLevel\":0,\"forignMobilePhone\":\"\",\"infoID\":0,\"insuranceCost\":0.0,\"insurance_fee\":0.0,\"clientId\":\"ccc123\",\"isFirstCoupon\":\"F\",\"isForeignCard\":\"\",\"isNeedCheckRisk\":\"T\",\"isOnline\":\"T\",\"isTempUser\":\"F\",\"isUidHasBlackCard\":\"\",\"latitude\":0.0,\"longitude\":0.0,\"mD5Password\":\"\",\"mobilePhone\":\"13499998985\",\"nationality\":\"\",\"nationalityofisuue\":\"\",\"needCheckBlackList\":\"T\",\"orderDate\":\"2015-09-10 17:00:15.679\",\"orderID\":1473238556,\"orderType\":1,\"packageAttachFee\":0.0,\"passengerInfoList\":[{\"passengerBirthday\":\"1975-09-01 00:00:00.000\",\"passengerCardIDType\":\"2\",\"passengerCardNo\":\"G0123456\",\"passengerCardNoType\":\"\",\"passengerGender\":\"M\",\"passengerName\":\"CHEN/LIANG\",\"passengerNationality\":\"CN\"}],\"paymentInfos\":[],\"persons\":0,\"postAddress\":\"\",\"prepayType\":\"NONE\",\"realReservationType\":0,\"refNo\":\"0\",\"referenceNo\":0,\"remark\":\"\",\"reservationType\":0,\"riskCountrolDeadline\":\"\",\"salesType\":1,\"segmentInfoList\":[{\"aAirPort\":\"XMN\",\"arrivaltime\":\"2015-09-25 16:50:00.000\",\"dAirPort\":\"PEK\",\"pataResult\":0,\"seatClass\":\"Y\",\"sequence\":1,\"subClass\":\"G\",\"takeofftime\":\"2015-09-25 13:40:00.000\",\"vehicleType\":0},{\"aAirPort\":\"CGK\",\"arrivaltime\":\"2015-09-25 23:40:00.000\",\"dAirPort\":\"XMN\",\"pataResult\":0,\"seatClass\":\"Y\",\"sequence\":2,\"subClass\":\"G\",\"takeofftime\":\"2015-09-25 19:10:00.000\",\"vehicleType\":0}],\"serverfrom\":\"flights.ctrip.com\",\"signUpDate\":\"2000-01-29 14:28:26.000\",\"subOrderType\":0,\"takeOffTime\":\"2015-09-25 13:40:00.000\",\"targetOrder\":0,\"tot_Oilfee\":0.0,\"tot_Tax\":0.0,\"totalDiscountAmount\":0.0,\"totalPenalty\":0.0,\"uid\":\"wwwwww\",\"urgencyLevel\":2,\"userIP\":\"58.246.10.89\",\"vipGrade\":0,\"wirelessClientNo\":\"\"},\"ext\":{\"CHANNEL\":\"EXECUTE\",\"descTimestamp\":2629004384096,\"reqId\":\"1075559582\"},\"requestTime\":\"2015-09-10 17:00:15.931\",\"requestReceive\":\"2015-09-10 17:00:15.904\"}", RiskFact.class);
        fact = eventDataMergeService.executeRedisPut(fact);
        fact.eventBody.remove("clientId");
        fact = eventDataMergeService.executeRedisPut(fact);
        System.out.println("fact: " + JSON.toJSONString(fact));
    }

}
