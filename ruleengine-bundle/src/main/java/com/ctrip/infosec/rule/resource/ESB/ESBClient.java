package com.ctrip.infosec.rule.resource.ESB;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import org.apache.commons.lang3.Validate;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.StringEntity;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;

import java.io.*;
import org.dom4j.DocumentException;

/*
 Created by lpxie on 15-3-20.
 */
public class ESBClient {

    private static final Logger logger = LoggerFactory.getLogger(ESBClient.class);
    private static ESBConfig esbConfig = new ESBConfig();

    static final String urlPrefix = GlobalConfig.getString("SOA.ESB.URL");
    static final String appId = GlobalConfig.getString("appId");

    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"SOA.ESB.URL\"配置项.");
        Validate.notEmpty(appId, "在GlobalConfig.properties里没有找到\"appId\"配置项.");
        esbConfig.setAppId(appId);
        esbConfig.setESBUrl(urlPrefix);
    }

    private static String requestWithSoap(String soapRequestContent) throws IOException {
        StringBuilder soapRequestSOAPData = new StringBuilder();
        soapRequestSOAPData.append("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">");
        soapRequestSOAPData.append("<SOAP-ENV:Body>");
        soapRequestSOAPData.append("<m:Request xmlns:m=\"http://tempuri.org/\">");
        soapRequestSOAPData.append(String.format("<m:requestXML><![CDATA[%s]]></m:requestXML>", soapRequestContent));
        soapRequestSOAPData.append("</m:Request>");
        soapRequestSOAPData.append("</SOAP-ENV:Body>");
        soapRequestSOAPData.append("</SOAP-ENV:Envelope>");

        String response = Request.Post(esbConfig.getESBUrl()).body(new StringEntity(soapRequestSOAPData.toString(), "UTF-8")).
                addHeader("Content-Type", "application/soap+xml; charset=utf-8").connectTimeout(1000).socketTimeout(10000).
                execute().returnContent().asString();
        return response;
    }

    private static String response(String soapResponseData) throws DocumentException {
        SAXReader reader = new SAXReader();
        StringReader read = new StringReader(soapResponseData);
        InputSource source = new InputSource(read);
        Document document = reader.read(source);
        Element rootElement = document.getRootElement();
        Element bodyElement = rootElement.element("Body");
        return bodyElement.getStringValue();
    }

    public static String requestESB(String requestType, String requestBody) throws Exception {
        check();
        String responseBody = null;
        StringBuilder requestContent = new StringBuilder();
        requestContent.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        requestContent.append("<Request>");
        if("AccCash.EasyPay.SaveRiskLevelData".equals(requestType)){
            requestContent.append(String.format("<Header UserID=\"670203\" RequestType=\"%s\" />", esbConfig.getAppId().toString(), requestType));
        }else {
            requestContent.append(String.format("<Header UserID=\"%s\" RequestType=\"%s\" />", esbConfig.getAppId().toString(), requestType));
        }
        requestContent.append(requestBody);
        requestContent.append("</Request>");

        String request = requestContent.toString();
        logger.info(Contexts.getLogPrefix() + "request: " + request);
        TraceLogger.traceLog("request: " + request);
        String soapResponseData = requestWithSoap(request);
        TraceLogger.traceLog("response: " + soapResponseData);
        logger.info(Contexts.getLogPrefix() + "response: " + soapResponseData);

        if (soapResponseData != null && !soapResponseData.isEmpty()) {
            responseBody = response(soapResponseData);
        }
        return responseBody;
    }
}
