package com.ctrip.infosec.rule.action;

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
 * Created by lpxie on 15-4-20.
 */
public class UpdateOrderStatus {

    private static Logger logger = LoggerFactory.getLogger(UpdateOrderStatus.class);
    private static StringBuffer content = new StringBuffer();

    public static Map updateOrderStatus(Map params) {
        beforeInvoke("OrderStatus.update");
        Map<String, String> result = new HashMap();
        try {
            content.append("<OrderID>" + params.get("OrderID") + "</OrderID>");
            content.append("<OrderType>" + params.get("OrderType") + "</OrderType>");
            content.append("<OrderStatus>" + params.get("OrderStatus") + "</OrderStatus>");
            content.append("<MerchantOrderID>" + params.get("MerchantOrderID") + "</MerchantOrderID>");
            content.append("<OrderTime>" + params.get("OrderTime") + "</OrderTime>");
            String xml = ESBClient.requestESB("Payment.CardRisk.InfoSecurity.OrderStatusRequest", "<OrderStatusRequest>" + content + "</OrderStatusRequest>");
            if (xml == null || xml.isEmpty()) {
                return result;
            }
            Document document = DocumentHelper.parseText(xml);
            String xpath = "/Response/OrderStatusResponse";
            List<Element> list = document.selectNodes(xpath);
            if (list == null || list.isEmpty()) {
                return result;
            }

            for (Element subElement : list) {
                Iterator iterator = subElement.elements().iterator();
                while (iterator.hasNext()) {
                    Element element = (Element) iterator.next();
                    result.put(element.getName(), element.getStringValue());
                }
            }
        } catch (Exception ex) {
            fault("OrderStatus.update");
            logger.error(Contexts.getLogPrefix() + "invoke UpdateOrderStatus.updateOrderStatus fault.", ex);
        } finally {
            content.setLength(0);
            afterInvoke("OrderStatus.update");
        }
        return result;
    }
}
