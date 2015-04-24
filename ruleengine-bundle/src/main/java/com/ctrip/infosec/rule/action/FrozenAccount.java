/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.action;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.ESB.ESBClient;
import org.dom4j.*;
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
 * 冻结/解冻钱包账户
 *
 * @author zhengby
 */
public class FrozenAccount {

    private static Logger logger = LoggerFactory.getLogger(FrozenAccount.class);
    private static StringBuffer content = new StringBuffer();

    public static Map frozen(String uid, String remark, String oper) {
        Map<String, String> result = new HashMap();
        result.put("uid", uid);
        result.put("operStatus", "T"); //T=冻解 F=解冻
        result.put("oper", oper);
        result.put("remark", remark);
        return frozenOrNot(result);
    }

    public static Map unfrozen(String uid, String remark, String oper) {
        Map<String, String> result = new HashMap();
        result.put("uid", uid);
        result.put("operStatus", "F"); //T=冻解 F=解冻
        result.put("oper", oper);
        result.put("remark", remark);
        return frozenOrNot(result);
    }

    /**
     * 添加是否解冻支付风控账户
     *
     * @param params
     * @return
     */
    private static Map frozenOrNot(Map params) {
        beforeInvoke();
        Map<String, String> result = new HashMap();
        try {
            content.append("<Uid>" + params.get("uid") + "</Uid>");
            content.append("<OperStatus>" + params.get("operStatus") + "</OperStatus>");
            content.append("<Oper>" + params.get("oper") + "</Oper>");
            content.append("<Remark>" + params.get("remark") + "</Remark>");
            //String newContent = new String(content.toString().getBytes("utf-8")).toString();
            String xml = ESBClient.requestESB("Payment.CardRisk.InfoSecurity.EnterFULogMessage", "<FULogMessageRequest>" + content + "</FULogMessageRequest>");
            if (xml == null || xml.isEmpty()) {
                return result;
            }
            Document document = DocumentHelper.parseText(xml);

            String xpath = "/Response/FULogMessageResponse";
            List<Element> list = document.selectNodes(xpath);
            if (list == null || list.isEmpty()) {
                /*xpath = "/Response/Header";
                Element header = (Element)document.selectSingleNode(xpath);
                Attribute resultCode = header.attribute("ResultCode");
                Attribute resultMsg = header.attribute("ResultMsg");
                result.put("resultCode",resultCode.getValue());
                result.put("resultMsg",resultMsg.getValue());*/
                result.put("result",xml);
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
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke FrozenAccount.frozenOrNot fault.", ex);
        } finally {
            content.setLength(0);
            afterInvoke("FrozenAccount.frozenOrNot");
        }
        return result;
    }
}
