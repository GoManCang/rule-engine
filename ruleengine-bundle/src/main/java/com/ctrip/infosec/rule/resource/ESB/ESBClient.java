package com.ctrip.infosec.rule.resource.ESB;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.thoughtworks.xstream.mapper.Mapper;
import org.apache.commons.lang3.Validate;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;

import java.io.*;

/*
 Created by lpxie on 15-3-20.
 */
public class ESBClient
{
    private static final Logger logger = LoggerFactory.getLogger(ESBClient.class);
    private static ESBConfig  esbConfig = new ESBConfig();

    static final String urlPrefix = GlobalConfig.getString("CardInfo.REST.URL.Prefix");
    static final String appId = GlobalConfig.getString("appId");
    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"CardInfo.REST.URL.Prefix\"配置项.");
        Validate.notEmpty(appId, "在GlobalConfig.properties里没有找到\"appId\"配置项.");
        esbConfig.setAppId(appId);
        esbConfig.setESBUrl(urlPrefix);
    }

    private static String requestWithSoap(String soapRequestContent)
    {
        StringBuilder soapRequestSOAPData = new StringBuilder();
        soapRequestSOAPData.append("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">");
        soapRequestSOAPData.append("<SOAP-ENV:Body>");
        soapRequestSOAPData.append("<m:Request xmlns:m=\"http://tempuri.org/\">");
        soapRequestSOAPData.append(String.format("<m:requestXML><![CDATA[%s]]></m:requestXML>",soapRequestContent));
        soapRequestSOAPData.append("</m:Request>");
        soapRequestSOAPData.append("</SOAP-ENV:Body>");
        soapRequestSOAPData.append("</SOAP-ENV:Envelope>");

        Response response = null;
        try
        {
            response = Request.Post(esbConfig.getESBUrl()).body(new StringEntity(soapRequestSOAPData.toString())).
                    addHeader("Content-Type", "application/soap+xml; charset=utf-8").connectTimeout(5000).socketTimeout(5000).
                    execute();
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        //FIXME 这里应该转换成httpResponse来得到statusCode 判断是否为200
        assert response != null;
        try
        {
            return response.returnContent().asString();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
        return null;
    }

    private static String response(String soapResponseData) throws IOException, DocumentException
    {
        SAXReader reader = new SAXReader();
        StringReader read = new StringReader(soapResponseData);
        InputSource source = new InputSource(read);
        Document document = reader.read(source);
        Element rootElement = document.getRootElement();
        Element bodyElement = rootElement.element("Body");
        return bodyElement.getStringValue();
    }


    public   static String requestESB(String requestType,String requestBody){
        check();
        String responseBody = null;
        try {
            StringBuilder requestContent = new StringBuilder();
            requestContent.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            requestContent.append("<Request>");
            requestContent.append(String.format("<Header UserID=\"%s\" RequestType=\"%s\" />", esbConfig.getAppId().toString(),requestType));
            requestContent.append(requestBody);
            requestContent.append("</Request>");

            String soapResponseData = requestWithSoap(requestContent.toString());
            if(soapResponseData!=null&&!soapResponseData.isEmpty())
                responseBody = response(soapResponseData);
        } catch (Exception e) {
            logger.warn(Contexts.getLogPrefix() + e.getMessage());
        }
        return responseBody;
    }
}
