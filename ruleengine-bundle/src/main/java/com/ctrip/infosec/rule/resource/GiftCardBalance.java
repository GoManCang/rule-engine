package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.meidusa.fastjson.JSON;
import org.apache.commons.lang3.Validate;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 2015/8/24.
 */
public class GiftCardBalance {

    private static final Logger logger = LoggerFactory.getLogger(GiftCardBalance.class);
    private static final String urlPrefix = GlobalConfig.getString("GetGiftBalance.REST.URL.Prefix");
    private static final int queryTimeout = GlobalConfig.getInteger("GetGiftBalance.query.timeout", 500);

    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"GetGiftBalance.REST.URL.Prefix\"配置项.");
    }

    /**
     * 获取账户的礼品卡余额信息
     *
     * @param uid
     * @return 返回余额信息 规则用到
     * ：TotalAvailableAmount（总余额）、TotalUnAvailableAmount（不可用余额）
     */
    public static Map query(String uid) {
        check();
        beforeInvoke("GiftCardBalance.query");
        Map<String, Object> response = null;
        try {
            String result = "";
            Map<String, String> request = new HashMap<>();
            request.put("UID", uid);
            result = Request.Post(urlPrefix + "/TravelMoney-OpenAPI-LipinAccountAPI/api/json/GetUAAmountByCategory")
                    .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(queryTimeout)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();
            response = JSON.parseObject(result, Map.class);
        } catch (Exception ex) {
            response = new HashMap<>();
            fault("GiftCardBalance.query");
            logger.error(Contexts.getLogPrefix() + "invoke GiftCardBalance.query fault.", ex);
            TraceLogger.traceLog("执行GiftCardBalance异常: " + ex.toString());
        } finally {
            afterInvoke("GiftCardBalance.query");
        }
        return response;
    }
}
