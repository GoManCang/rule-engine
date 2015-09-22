/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;

/**
 * 同盾
 *
 * @author zhengby
 */
public class TongDun {

    static final String serviceName = "ThirdServiceClient";
    static final String operationName_reg = "api.fraudmetrix.cn_RiskServiceRegister";
    static final String operationName_trade = "api.fraudmetrix.cn_RiskServiceTrade";

    /**
     * 同盾的ip和手机号注册事件查询服务
     *
     * @param ip
     * @param mobile
     * @return
     * {"reason_code":null,"final_decision":"Accept","seq_id":"1442309654522-72705995","final_score":0,"success":true}
     */
    public static Map<String, Object> queryRegEvent(String ip, String mobile) {
        if (StringUtils.isBlank(ip) && StringUtils.isBlank(mobile)) {
            return Collections.EMPTY_MAP;
        }
        Map params = new HashMap<String, Object>();
        params.put("account_mobile", mobile);
        params.put("ip_address", ip);
        return DataProxy.queryForMap(serviceName, operationName_reg, params);
    }

    /**
     * 同盾的ip和手机号交易事件查询服务
     *
     * @param ip
     * @param mobile
     * @return
     * {"reason_code":null,"final_decision":"Accept","seq_id":"1442309654522-72705995","final_score":0,"success":true}
     */
    public static Map<String, Object> queryTradeEvent(String ip, String mobile) {
        if (StringUtils.isBlank(ip) && StringUtils.isBlank(mobile)) {
            return Collections.EMPTY_MAP;
        }
        Map params = new HashMap<String, Object>();
        params.put("account_mobile", mobile);
        params.put("ip_address", ip);
        return DataProxy.queryForMap(serviceName, operationName_trade, params);
    }
}
