/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.model.RiskResult;
import com.ctrip.infosec.rule.Contexts;
import com.meidusa.fastjson.JSON;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author zhengby
 */
@Service
public class CallbackMessageSender {

    private static Logger logger = LoggerFactory.getLogger(CallbackMessageSender.class);
    @Resource(name = "template_callback")
    private AmqpTemplate template;

    public void sendToPD(RiskResult result) {
        String routingKey = StringUtils.substring(result.getEventPoint(), 2, 5);
        String message = JSON.toJSONString(result);
        logger.info(Contexts.getLogPrefix() + "send callback message, routingKey=" + routingKey + ", message=" + message);
        template.convertAndSend(routingKey, message);
        logger.info(Contexts.getLogPrefix() + "send callback message, OK.");
    }
}
