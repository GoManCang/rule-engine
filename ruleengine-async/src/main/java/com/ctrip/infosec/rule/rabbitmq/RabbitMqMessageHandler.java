/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.executor.PostRulesExecutorService;
import com.ctrip.infosec.rule.executor.PreRulesExecutorService;
import com.ctrip.infosec.rule.executor.RulesExecutorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 *
 * @author zhengby
 */
@Service("rabbitMqMessageHandler")
public class RabbitMqMessageHandler {

    private static Logger logger = LoggerFactory.getLogger(RabbitMqMessageHandler.class);

    @Autowired
    private RulesExecutorService rulesExecutorService;
    @Autowired
    private PreRulesExecutorService preRulesExecutorService;
    @Autowired
    private PostRulesExecutorService postRulesExecutorService;

    public void handleMessage(Object factTxt) {
        logger.info("REST: fact=" + factTxt);
        RiskFact fact = JSON.parseObject((String) factTxt, RiskFact.class);
        Contexts.setLogPrefix("[" + fact.eventPoint + "][" + fact.eventId + "] ");
        try {
            // 执行预处理
            preRulesExecutorService.executePreRules(fact, true);
            // 执行异步规则
            rulesExecutorService.executeAsyncRules(fact);
            // 执行后处理
            postRulesExecutorService.executePostRules(fact, true);
        } catch (Throwable ex) {
            // TODO: 处理异常
            logger.error(Contexts.getLogPrefix() + "invoke query exception.", ex);
        }
    }
}
