package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.ESB.ESBClient;
import org.apache.commons.lang3.StringUtils;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 2015/8/26.
 */
public class UidSecInfo {
    private static final Logger logger = LoggerFactory.getLogger(UidSecInfo.class);

    public static Map query(String uid) {
        beforeInvoke();
        Map<String, String> result = new HashMap();
        try {
            if (StringUtils.isBlank(uid)) {
                return result;
            }
            String xml = ESBClient.requestESB("Payment.Base.PaymentPwdWS.GetPaymentPasswordDetail", "<GetPaymentPasswordDetailRequest><CustomerID>" + uid + "</CustomerID></GetPaymentPasswordDetailRequest>");
            if (xml == null || xml.isEmpty()) {
                return result;
            }
            Document document = DocumentHelper.parseText(xml);
            String xpath = "/Response/GetPaymentPasswordDetailResponse";
            List<Element> list = document.selectNodes(xpath);
            if (list == null || list.isEmpty()) {
                return result;
            }

            for (Element creditCard : list) {
                Iterator iterator = creditCard.elements().iterator();
                while (iterator.hasNext()) {
                    Element element = (Element) iterator.next();
                    result.put(element.getName(), element.getStringValue());
                }
            }
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke UidSecInfo.query fault.", ex);
            TraceLogger.traceLog("执行UidSecInfo异常: " + ex.toString());
        } finally {
            afterInvoke("UidSecInfo.query");
        }
        return result;
    }
}
