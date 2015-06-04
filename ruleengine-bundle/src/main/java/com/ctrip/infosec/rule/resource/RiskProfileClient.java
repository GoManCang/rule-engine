package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.sec.userprofile.client.service.RiskProfileClientConfig;
import org.apache.commons.lang3.Validate;

/**
 * Created by lpxie on 15-6-3.
 */
public class RiskProfileClient {

    static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");

    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.REST.URL.Prefix\"配置项.");
    }

    static void init() {
        check();
        RiskProfileClientConfig client = new RiskProfileClientConfig();
        client.init(urlPrefix);
    }
}
