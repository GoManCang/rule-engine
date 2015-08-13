package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import org.apache.commons.lang.Validate;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import com.google.common.collect.ImmutableMap;
import java.util.HashMap;
import java.util.List;

/**
 * Created by lpxie on 15-8-12. 这个类用作调用Flow4j的黑白名单
 */
public class BWListRuleEngine {

    private final static Logger log = LoggerFactory.getLogger(BWListRuleEngine.class);
    private final static String urlPrefix = GlobalConfig.getString("BWList.URL.Prefix");
    private final static int queryTimeout = GlobalConfig.getInteger("BWList.timeout", 500);

    /**
     *
     * @param accountParams 账户黑白名单参数
     * @param bwlistParams 支付黑白名单参数
     *
     * Map accountParams = new HashMap<>();
     * accountParams.put("uid","test12345678");
     * 返回的结果是列表 [{ "ruleType": "ACCOUNT", "ruleID": 0, "ruleName": "CREDIT-EXCHANGE", "riskLevel": 295, "ruleRemark": "" }]
     * @return
     */
    public static List<Map<String, String>> check(Map accountParams, Map bwlistParams) {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"BWList.URL.Prefix\"配置项.");
        beforeInvoke();
        ArrayList<Map<String, String>> result = new ArrayList<>();
        try {
            if (accountParams == null) {
                accountParams = new HashMap();
            }
            if (bwlistParams != null) {
                accountParams.put("blacklist", bwlistParams);
            }
            Map fact = ImmutableMap.of("eventBody", accountParams);
            String requestTxt = Utils.JSON.toJSONString(fact);
            TraceLogger.traceLog("REQUEST: " + requestTxt);
            String responseTxt = Request.Post(urlPrefix + "/flowtable4j/rest/checkBWGList")
                    .body(new StringEntity(requestTxt, ContentType.APPLICATION_JSON))
                    .connectTimeout(100)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();
            TraceLogger.traceLog("RESPONSE: " + responseTxt);

            Map response = Utils.JSON.parseObject(responseTxt, Map.class);
            String status = response.get("status").toString();
            if (status.equals("OK")) {
                ArrayList<Map<String, String>> temp = (ArrayList<Map<String, String>>) response.get("results");
                result.addAll(temp);
            }
        } catch (Exception ex) {
            fault();
            log.error(Contexts.getLogPrefix() + "invoke BWRuleEngine.check fault.", ex);
            TraceLogger.traceLog("执行BWRuleEngine异常: " + ex.toString());
        } finally {
            afterInvoke("BWRuleEngine.check");
        }

        return result;
    }
}
