package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.ESB.ESBClient;
import com.ctrip.infosec.rule.util.MonitorAgent;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.*;

/*
 * Created by lpxie on 15-3-20.
 */
public class CardInfo extends MonitorAgent {

    private static final Logger logger = LoggerFactory.getLogger(CardInfo.class);

    /**
     * 这里的serviceName必须是“getinfo”
     */
    public static Map query(String serviceName, Map<String, Object> params) {
        beforeInvoke();
        Map<String, String> result = new HashMap();
        try {
            String xml = ESBClient.requestESB("AccCash.CreditCard.GetCreditCardInfo", "<GetCreditCardInfoRequest><CardInfoId>" + params.get("cardInfoId") + "</CardInfoId></GetCreditCardInfoRequest>");
            if (xml == null || xml.isEmpty()) {
                return result;
            }
//            SAXReader reader = new SAXReader();
            Document document = DocumentHelper.parseText(xml);
            String xpath = "/Response/GetCreditCardInfoResponse/CreditCardItems/CreditCardInfoResponseItem";
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
            logger.error(Contexts.getLogPrefix() + "invoke CardInfo.query fault.", ex);
        } finally {
            afterInvoke("CardInfo.query");
        }
        return result;
    }
}
