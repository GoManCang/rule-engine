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
 * 岂安
 *
 * @author zhengby
 */
public class QiAn {

    static final String serviceName = "ThirdServiceClient";
    static final String operationName = "api.bigsec.com_checkvip";

    /**
     * 凯安的ip和手机号注册事件查询服务
     *
     * @param ip
     * @param mobile
     * @return
     * {"msg":null,"success":1,"mobile":{"score":null,"is_notreal":null},"ip":{"is_proxy":0,"score":50.0,"ip":"218.17.231.209"}}
     */
    public static Map<String, Object> queryRegEvent(String ip, String mobile) {
        if (StringUtils.isBlank(ip) && StringUtils.isBlank(mobile)) {
            return Collections.EMPTY_MAP;
        }
        Map params = new HashMap<String, Object>();
        params.put("mobile", mobile);
        params.put("ip", ip);
        return DataProxy.queryForMap(serviceName, operationName, params);
    }
}
