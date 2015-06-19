/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.rest;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.executor.PostRulesExecutorService;
import com.ctrip.infosec.rule.executor.PreRulesExecutorService;
import com.ctrip.infosec.rule.executor.EventDataMergeService;
import com.ctrip.infosec.rule.executor.RulesExecutorService;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * 规则同步执行接口
 *
 * @author zhengby
 */
@Controller
@RequestMapping(value = "/rule")
public class RuleEngineRESTfulController {

    private static Logger logger = LoggerFactory.getLogger(RuleEngineRESTfulController.class);

    @Autowired
    private RulesExecutorService rulesExecutorService;
    @Autowired
    private PreRulesExecutorService preRulesExecutorService;
    @Autowired
    private EventDataMergeService eventDataMergeService;
    @Autowired
    private PostRulesExecutorService postRulesExecutorService;

    @RequestMapping(value = "/query", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<?> query(@RequestBody String factTxt) {
        logger.info("REST: fact=" + factTxt);
        RiskFact fact = JSON.parseObject(factTxt, RiskFact.class);
        Contexts.setLogPrefix("[" + fact.eventPoint + "][" + fact.eventId + "] ");
        SarsMonitorContext.setLogPrefix(Contexts.getLogPrefix());
        try {
            // 执行Redis读取
            eventDataMergeService.executeRedisGet(fact);
            // 执行预处理
            preRulesExecutorService.executePreRules(fact, false);
            //执行推送数据到Redis
            eventDataMergeService.executeRedisPut(fact);
            // 执行同步规则
            rulesExecutorService.executeSyncRules(fact);
        } catch (Throwable ex) {
            if (fact.finalResult == null) {
                fact.setFinalResult(Constants.defaultResult);
            }
            logger.error(Contexts.getLogPrefix() + "invoke query exception.", ex);
        }
        return new ResponseEntity(fact, HttpStatus.OK);
    }

    /**
     * POST版本的规则验证接口
     *
     * @param factTxt
     * @return
     */
    @RequestMapping(value = "/verify", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<?> verify(@RequestParam(value = "fact", required = true) String factTxt) {
        logger.info("REST: fact=" + factTxt);
        RiskFact fact = JSON.parseObject(factTxt, RiskFact.class);
        Contexts.setLogPrefix("[" + fact.eventPoint + "][" + fact.eventId + "] ");
        SarsMonitorContext.setLogPrefix(Contexts.getLogPrefix());
        try {
            // 执行订单合并
            eventDataMergeService.executeRedisOption(fact);
            // 执行预处理
            preRulesExecutorService.executePreRules(fact, false);
            // 执行同步规则
            rulesExecutorService.executeSyncRules(fact);
        } catch (Throwable ex) {
            if (fact.finalResult == null) {
                fact.setFinalResult(Constants.defaultResult);
            }
            logger.error(Contexts.getLogPrefix() + "invoke query exception.", ex);
        }
        return new ResponseEntity(fact, HttpStatus.OK);
    }
}
