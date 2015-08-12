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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 15-8-12. 这个类用作调用Flow4j的黑白名单
 */
public class CheckBWGList {

    private final static Logger log = LoggerFactory.getLogger(CheckBWGList.class);
    private final static String urlPrefix = GlobalConfig.getString("BWList.URL.Prefix");
    private final static int queryTimeout = GlobalConfig.getInteger("BWList.timeout", 200);

    private static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"BWList.URL.Prefix\"配置项.");
    }

    /**
     *
     * @param request Map params = new HashMap<>(); Map eventBody = new
     * HashMap(); eventBody.put("uid","test12345678");
     * params.put("eventBody",eventBody); 返回的结果是列表 [{ "ruleType": "ACCOUNT",
     * "ruleID": 0, "ruleName": "CREDIT-EXCHANGE", "riskLevel": 295,
     * "ruleRemark": "" }]
     * @return
     */
    public static ArrayList<Map<String, String>> query(Map request) {
        check();
        beforeInvoke();
        ArrayList<Map<String, String>> result = new ArrayList<>();
        try {
            String responseTxt = Request.Post(urlPrefix + "/flowtable4j/rest/checkBWGList")
                    .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(queryTimeout)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();

            Map response = Utils.JSON.parseObject(responseTxt, Map.class);
            String status = response.get("status").toString();
            if (status.equals("OK")) {
                ArrayList<Map<String, String>> temp = (ArrayList<Map<String, String>>) response.get("results");
                result.addAll(temp);
            } else {
                log.warn("检查黑白名单异常，返回的状态为：" + status);
            }
        } catch (Exception ex) {
            fault();
            log.error(Contexts.getLogPrefix() + "invoke CheckBWGList.query fault.", ex);
            TraceLogger.traceLog("执行CheckBWGList异常: " + ex.toString());
        } finally {
            afterInvoke("CheckBWGList.query");
        }

        return result;
    }
}
