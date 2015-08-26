package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import org.apache.commons.lang3.Validate;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.StringEntity;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;

import java.io.StringReader;
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
public class WalletAccountInfo {
    private static final Logger logger = LoggerFactory.getLogger(WalletAccountInfo.class);
    private static String url = GlobalConfig.getString("Wallet.ESB.URL");

    static void check() {
        Validate.notEmpty(url, "在GlobalConfig.properties里没有找到\"Wallet.ESB.URL\"配置项.");
    }

    public static Map query(String uid){
        check();
        beforeInvoke();
        Map result = new HashMap();
        try {
            String response = "";
            StringBuilder soapRequestSOAPData = new StringBuilder();
            soapRequestSOAPData.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            soapRequestSOAPData.append("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:acc=\"http://www.ctrip.com/cwallet/ws/account\"> ");
            soapRequestSOAPData.append("<soapenv:Header/>");
            soapRequestSOAPData.append("<soapenv:Body>");
            soapRequestSOAPData.append("<acc:GetAccountByMerchant>");
            soapRequestSOAPData.append("<GetAccountByMerchantReq>");
            soapRequestSOAPData.append("<MerchantUid>"+uid+"</MerchantUid>");
            soapRequestSOAPData.append("<MerchantId>CTRP</MerchantId>");
            soapRequestSOAPData.append("</GetAccountByMerchantReq>");
            soapRequestSOAPData.append("</acc:GetAccountByMerchant>");
            soapRequestSOAPData.append("</soapenv:Body>");
            soapRequestSOAPData.append("</soapenv:Envelope>");

            response = Request.Post(url).body(new StringEntity(soapRequestSOAPData.toString(), "UTF-8")).
                    addHeader("Content-Type", "application/soap+xml; charset=utf-8").connectTimeout(1000).socketTimeout(10000).
                    execute().returnContent().asString();
            result = response(response);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke WalletAccountInfo.query fault.", ex);
            TraceLogger.traceLog("执行WalletAccountInfo异常: " + ex.toString());
        } finally {
            afterInvoke("WalletAccountInfo.query");
        }

        return result;
    }

    private static Map response(String data) throws DocumentException {
        //这里把前面和后面的部分删除掉  这里因为没办法全部解析 所以用这种方式截取其中的内容
        data = data.substring(data.indexOf("GetAccountByMerchantRsp")-1,data.lastIndexOf("GetAccountByMerchantRsp")+24);
        SAXReader reader = new SAXReader();
        StringReader read = new StringReader(data);
        InputSource source = new InputSource(read);
        Document document = reader.read(source);
        Map result = new HashMap();
        String xpath = "/GetAccountByMerchantRsp";
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
        return result;
    }
}
