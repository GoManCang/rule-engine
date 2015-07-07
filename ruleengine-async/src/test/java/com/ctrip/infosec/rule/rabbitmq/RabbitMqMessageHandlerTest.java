package com.ctrip.infosec.rule.rabbitmq;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

import static org.junit.Assert.*;

/**
 * Created by yxjiang on 2015/7/7.
 */
@ContextConfiguration("classpath*:spring/ruleengine*.xml")
public class RabbitMqMessageHandlerTest extends AbstractJUnit4SpringContextTests {
    @Autowired
    RabbitMqMessageHandler handler;

    @Test
    public void testHandleMessage() throws Exception {
        String msg = "{\n" +
                "  \"eventPoint\" : \"CP0026001\",\n" +
                "  \"eventId\" : \"CP0026001\",\n" +
                "  \"eventBody\" : {\n" +
                "    \"UserProfileInfo\" : {\n" +
                "      \"CUSCHARACTER\" : \"REPEAT\"\n" +
                "    },\n" +
                "    \"aCity\" : \"0\",\n" +
                "    \"checkType\" : \"1\",\n" +
                "    \"contactEMail\" : \"endl@citiz.net\",\n" +
                "    \"contactName\" : \"测试一\",\n" +
                "    \"contactTel\" : \"\",\n" +
                "    \"dCity\" : \"0\",\n" +
                "    \"departureDate\" : \"2015-10-01 00:00:00.000\",\n" +
                "    \"isOnline\" : \"T\",\n" +
                "    \"latitude\" : \"0\",\n" +
                "    \"longitude\" : \"0\",\n" +
                "    \"mobilePhone\" : \"15800000000\",\n" +
                "    \"optionItems\" : [ ],\n" +
                "    \"orderAmount\" : \"8213\",\n" +
                "    \"orderDate\" : \"2015-07-07 16:47:04.000\",\n" +
                "    \"orderID\" : \"1143578232\",\n" +
                "    \"orderInfoExternalURL\" : \"\",\n" +
                "    \"orderToSignUpDate\" : \"64659\",\n" +
                "    \"orderType\" : \"22\",\n" +
                "    \"paymentInfos\" : [ ],\n" +
                "    \"postActions\" : { },\n" +
                "    \"productName\" : \"歌诗达邮轮【大西洋号test】上海上船 航线子名称-超长子名称/r/n~超长子名称~超长子名称~超长子名称~超长子名称~超长子名称~超长子名称~超长子 17日游\",\n" +
                "    \"referenceNo\" : \"1315070713000005311\",\n" +
                "    \"sendTickerAddr\" : \"\",\n" +
                "    \"serverfrom\" : \"www.ctrip.com\",\n" +
                "    \"uid\" : \"test111111\",\n" +
                "    \"uidCrmMemberInfo\" : {\n" +
                "      \"bindedEmail\" : \"test@163.com\",\n" +
                "      \"bindedMobilePhone\" : \"13616667784\",\n" +
                "      \"birth\" : \"1997-01-01T00:00:00\",\n" +
                "      \"city\" : \"2\",\n" +
                "      \"ctripcardno\" : \"1680000044\",\n" +
                "      \"email\" : \"hj_liu@ctrip.com\",\n" +
                "      \"experience\" : \"-1649307515\",\n" +
                "      \"gender\" : \"M\",\n" +
                "      \"mD5Password\" : \"E10ADC3949BA59ABBE56E057F20F883E\",\n" +
                "      \"maxGrade\" : \"10\",\n" +
                "      \"mileageIncluding\" : \"HF\",\n" +
                "      \"mobilePhone\" : \"13355555555\",\n" +
                "      \"scSaleCardEmp\" : \"yanxie\",\n" +
                "      \"signupIP\" : \"172.16.144.14\",\n" +
                "      \"signupdate\" : \"2008-02-20T13:25:32\",\n" +
                "      \"sourceid\" : \"8\",\n" +
                "      \"tel\" : \"777777777*2222\",\n" +
                "      \"uid\" : \"test111111\",\n" +
                "      \"updateTime\" : \"2014-05-14T16:42:14\",\n" +
                "      \"userName\" : \"test\",\n" +
                "      \"vip\" : \"F\",\n" +
                "      \"vipGrade\" : \"30\"\n" +
                "    },\n" +
                "    \"userIP\" : \"\",\n" +
                "    \"userInfos\" : [ {\n" +
                "      \"visitorCardNo\" : \"\",\n" +
                "      \"visitorContactInfo\" : \"15800000000\",\n" +
                "      \"visitorName\" : \"CE/SHIYI\",\n" +
                "      \"visitorNationality\" : \"CN\"\n" +
                "    }, {\n" +
                "      \"visitorCardNo\" : \"\",\n" +
                "      \"visitorContactInfo\" : \"13000000000\",\n" +
                "      \"visitorName\" : \"sa/cun\",\n" +
                "      \"visitorNationality\" : \"CN\"\n" +
                "    } ]\n" +
                "  },\n" +
                "  \"requestTime\" : \"2015-07-07 16:47:05.726\"\n" +
                "}";
        handler.handleMessage(msg);
    }
}