/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.Constants;
import javax.annotation.Resource;

import org.apache.commons.collections.MapUtils;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.stereotype.Service;

import com.ctrip.infosec.common.model.RiskEvent;
import com.ctrip.infosec.common.model.RiskFact;
import com.meidusa.fastjson.JSON;

/**
 *
 * @author zhengby
 */
@Service
public class OfflineMessageSender {

    @Resource(name = "template_offline4j")
    private AmqpTemplate template;
    private final String defaultRoutingKey = "offline4j";

    public void sendToOffline(RiskFact fact) {

        RiskEvent event = dataConvert(fact);

        //如果CP0001002支付授权,才进行发送
        //需要字段合并策略,orderType 为 1
        String eventPoint = fact.getEventPoint();
        String orderType = MapUtils.getString(fact.getEventBody(), "orderType");

        if ("CP0001002".equals(eventPoint) && "1".equals(orderType)) {

            template.convertAndSend(defaultRoutingKey, JSON.toJSONString(event));

        }

    }
    
    public void sendToOffline(Object obj) {
    	
    	template.convertAndSend(defaultRoutingKey, JSON.toJSONString(obj));
    }

    private RiskEvent dataConvert(RiskFact fact) {

        RiskEvent event = new RiskEvent();

        event.setEventId(fact.getEventId());
        event.setEventPoint(fact.getEventPoint());
        event.setEventBody(fact.getEventBody());

        Integer obj = MapUtils.getInteger(fact.getFinalResult(), Constants.riskLevel);
        if (null != obj) {
            event.setRiskLevel(obj);
        }

        return event;
    }
}
