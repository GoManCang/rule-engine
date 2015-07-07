package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.ESB.ESBClient;
import com.ctrip.infosec.rule.resource.model.ESBResponse;
import com.ctrip.infosec.rule.resource.model.Header;
import com.ctrip.infosec.rule.resource.model.SaveRiskLevelDataRequest;
import com.ctrip.infosec.rule.resource.model.SaveRiskLevelDataResponse;
import com.thoughtworks.xstream.XStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.ctrip.infosec.common.SarsMonitorWrapper.*;

/**
 * Created by yxjiang on 2015/7/7.
 */
public class RiskLevelData {
    private static final Logger logger = LoggerFactory.getLogger(RiskLevelData.class);
    static XStream xstream = new XStream();

    static {
        xstream.alias("SaveRiskLevelDataRequest", SaveRiskLevelDataRequest.class);
        xstream.alias("Response", ESBResponse.class);
        xstream.alias("Header", Header.class);
        xstream.alias("SaveRiskLevelDataResponse", SaveRiskLevelDataResponse.class);
    }

    public static SaveRiskLevelDataResponse save(long reqId, int riskLevel, long orderId){
        beforeInvoke("SaveRiskLevelData");
        SaveRiskLevelDataRequest request = new SaveRiskLevelDataRequest();
        request.setResID(reqId);
        request.setReqID(reqId);
        request.setOrderID(orderId);
        request.setRiskLevel(riskLevel);
        String xml = xstream.toXML(request);
        SaveRiskLevelDataResponse result = null;
        try {
            String respXml = ESBClient.requestESB("AccCash.EasyPay.SaveRiskLevelData", xml);
            result = ((ESBResponse)xstream.fromXML(respXml)).getSaveRiskLevelDataResponse();
        } catch (Exception ex) {
            fault("SaveRiskLevelData");
            logger.error(Contexts.getLogPrefix() + "invoke SaveRiskLevelData fault.", ex);
        } finally {
            afterInvoke("SaveRiskLevelData");
        }
        return result;
    }
}
