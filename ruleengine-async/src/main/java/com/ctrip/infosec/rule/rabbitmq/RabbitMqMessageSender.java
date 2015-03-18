/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 *
 * @author zhengby
 */
@Service
public class RabbitMqMessageSender {

    @Autowired
    private AmqpTemplate template;
    private final String defaultRoutingKey = "datadispatcher";

    public void sendToDataDispatcher(RiskFact fact) {
        template.convertAndSend(defaultRoutingKey, JSON.toJSONString(fact));
    }
}
