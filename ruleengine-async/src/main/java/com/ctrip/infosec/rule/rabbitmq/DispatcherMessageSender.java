/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.DistributionChannel;
import com.ctrip.infosec.configs.utils.BeanMapper;
import com.ctrip.infosec.sars.util.Collections3;
import com.google.common.collect.Maps;
import com.meidusa.fastjson.JSON;
import java.util.Map;
import java.util.Set;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;

/**
 *
 * @author zhengby
 */
@Service
public class DispatcherMessageSender {

    @Resource(name = "template_datadispatcher")
    private AmqpTemplate template;
    private final String defaultRoutingKey = "datadispatcher";

    public void sendToDataDispatcher(RiskFact fact) {
        Set<DistributionChannel> channels = Configs.getDistributionChannelsByEventPoint(fact.eventPoint);
        String routingKey = StringUtils.join(Collections3.extractToList(channels, "channelNo"), ",");
        boolean withScene = Constants.eventPointsWithScene.contains(fact.eventPoint);
        if (withScene) {
            RiskFact factCopy = BeanMapper.copy(fact, RiskFact.class);
            if (!factCopy.resultsGroupByScene.isEmpty()) {
                Map<String, Object> finalResult = Maps.newHashMap();
                finalResult.put(Constants.riskLevel, 0);
                finalResult.put(Constants.riskMessage, "PASS");
                for (Map<String, Object> rs : factCopy.resultsGroupByScene.values()) {
                    finalResult = compareAndReturn(finalResult, rs);
                }
                factCopy.setFinalResult(Maps.newHashMap(finalResult));
                factCopy.finalResult.remove(Constants.async);
                factCopy.finalResult.remove(Constants.timeUsage);

            }
//            template.convertAndSend(routingKey, JSON.toJSONString(factCopy));
            template.convertAndSend(defaultRoutingKey, JSON.toJSONString(factCopy));
        } else {
//            template.convertAndSend(routingKey, JSON.toJSONString(fact));
            template.convertAndSend(defaultRoutingKey, JSON.toJSONString(fact));
        }
    }

    /**
     * 返回分值高的结果作为finalResult
     */
    Map<String, Object> compareAndReturn(Map<String, Object> oldResult, Map<String, Object> newResult) {
        if (newResult == null) {
            return oldResult;
        }
        if (oldResult == null) {
            return newResult;
        }
        int newRriskLevel = MapUtils.getInteger(newResult, Constants.riskLevel, 0);
        int oldRriskLevel = MapUtils.getInteger(oldResult, Constants.riskLevel, 0);
        if (newRriskLevel > oldRriskLevel) {
            return newResult;
        }
        return oldResult;
    }
}
