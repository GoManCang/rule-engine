package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.ESB.ESBClient;
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
 * Created by lpxie on 15-4-9.
 */
public class CustomerInfo {

    private static final Logger logger = LoggerFactory.getLogger(CustomerInfo.class);

    public static Map<String, String> queryByUid(String uid) {
        Map params = new HashMap();
        params.put("uid", uid);
        return query(params);
    }

    public static Map<String, String> query(Map<String, Object> params) {
        beforeInvoke("CustomerInfo.query");
        Map<String, String> result = new HashMap();
        try {
            String xml = ESBClient.requestESB("Customer.User.GetCustomerInfo", "<GetCustomerInfoRequest><UID>" + params.get("uid") + "</UID></GetCustomerInfoRequest>");
            if (xml == null || xml.isEmpty()) {
                return result;
            }
            Document document = DocumentHelper.parseText(xml);
            String xpath = "/Response/GetCustomerInfoResponse";
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
            fault("CustomerInfo.query");
            logger.error(Contexts.getLogPrefix() + "invoke CustomerInfo.query fault.", ex);
        } finally {
            afterInvoke("CustomerInfo.query");
        }
        return result;
    }
}
