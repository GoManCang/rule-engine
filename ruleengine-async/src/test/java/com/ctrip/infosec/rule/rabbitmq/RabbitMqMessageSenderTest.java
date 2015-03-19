/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine*.xml"})
public class RabbitMqMessageSenderTest {

    @Autowired
    private AmqpTemplate template;

    @Test
    public void testSend() {
        System.out.println("send");
        RiskFact fact = JSON.parseObject("{\n"
                + "  \"eventPoint\" : \"CP0011004\",\n"
                + "  \"eventBody\" : {\n"
                + "    \"actualAmount\" : \"327.0\",\n"
                + "    \"amount\" : \"327.0\",\n"
                + "    \"bizType\" : \"10\",\n"
                + "    \"bookingDate\" : \"2015-03-19 10:09:35\",\n"
                + "    \"channelID\" : \"4897\",\n"
                + "    \"contactInfo\" : \"{\\\"Name\\\":\\\"ZHANG/XIAOQIAN\\\",\\\"Tel\\\":\\\"\\\",\\\"Mobile\\\":\\\"018661958397\\\",\\\"Email\\\":\\\"zhxq330@163.com\\\",\\\"Fax\\\":\\\"\\\",\\\"ConfirmType\\\":\\\"EML\\\"}\",\n"
                + "    \"currency\" : \"RMB\",\n"
                + "    \"firstDepartureTime\" : \"2015-04-05 07:40:00\",\n"
                + "    \"isHide\" : \"false\",\n"
                + "    \"isPartial\" : \"\",\n"
                + "    \"itemInfos\" : \"[{\\\"ArrivalTime\\\":\\\"2015-04-05 08:55:00\\\",\\\"Description\\\":\\\"^若改期费与升舱费同时发生,两者同时收取\\\",\\\"FlightNo\\\":\\\"MU5512\\\",\\\"FlightWay\\\":\\\"S\\\",\\\"FromAddress\\\":\\\"TAO\\\",\\\"FromCityId\\\":\\\"7\\\",\\\"FromCityName\\\":\\\"青岛\\\",\\\"IsSurface\\\":\\\"F\\\",\\\"OrderCategory\\\":\\\"Flight\\\",\\\"Price\\\":277.0,\\\"SubClass\\\":\\\"Z\\\",\\\"TakeOffTime\\\":\\\"2015-04-05 07:40:00\\\",\\\"ToAddress\\\":\\\"PVG\\\",\\\"ToCityId\\\":\\\"2\\\",\\\"ToCityName\\\":\\\"上海\\\"}]\",\n"
                + "    \"message_CreateTime\" : \"2015-3-19 10:09:46\",\n"
                + "    \"operateTime\" : \"2015-03-19 10:09:44\",\n"
                + "    \"operators\" : \"\",\n"
                + "    \"orderDescription\" : \"已扣款出票中\",\n"
                + "    \"orderId\" : \"1264737658\",\n"
                + "    \"orderStatus\" : \"FLIGHT_CHARGED_TICKETING\",\n"
                + "    \"orderType\" : \"国内\",\n"
                + "    \"orderVersion\" : \"1:1\",\n"
                + "    \"passengers\" : \"[{\\\"AgeType\\\":\\\"ADU\\\",\\\"BirthDate\\\":\\\"1984-3-30 0:00:00\\\",\\\"CardNo\\\":\\\"G21279431\\\",\\\"CardType\\\":\\\"2\\\",\\\"Gender\\\":\\\"M\\\",\\\"Mobile\\\":\\\"18661958397\\\",\\\"Name\\\":\\\"ZHANG/XIAOQIAN\\\"}]\",\n"
                + "    \"remarks\" : \"\",\n"
                + "    \"serverFrom\" : \"flights.ctrip.com\",\n"
                + "    \"sourceFromCode\" : \"Web\",\n"
                + "    \"specialPriceType\" : \"SI\",\n"
                + "    \"ticketStatus\" : \"A\",\n"
                + "    \"uid\" : \"D65131299\"\n"
                + "  }\n"
                + "}", RiskFact.class);
        
        for (int i = 0; i < 100; i++) {
            template.convertAndSend("infosec.ruleengine.queue", JSON.toJSONString(fact));
        }
    }

}
