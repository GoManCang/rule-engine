package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.sec.userprofile.vo.content.request.DataProxyRequest;
import com.ctrip.sec.userprofile.vo.content.response.DataProxyResponse;
import org.apache.commons.lang3.Validate;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

/**
 * 根据卡的id和卡的rule来获取卡的信息 返回的是一个map，包含了当前卡的相关信息 Created by lpxie on 15-7-16.
 */
public class ForeignCardInfo {

    private static final Logger logger = LoggerFactory.getLogger(ForeignCardInfo.class);

    private static Map<String, Map> foreignCardInfos = new HashMap<>();

    private static boolean isInit = false;

    static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");

    private static final int queryTimeout = GlobalConfig.getInteger("DataProxy.query.timeout", 10000);

    static Lock lock = new ReentrantLock();

    private static void init() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.REST.URL.Prefix\"配置项.");
        if (!isInit) {
            lock.lock();
            try {
                getData();
                isInit = true;
            } catch (Exception exp) {
                logger.warn("从DataProxy获取外卡信息的记录异常:" + exp.getMessage());
            } finally {
                lock.unlock();
            }
        }
    }

    private static void getData() {
        String serviceName = "ConvertService";
        String operationName = "getForeignCardInfo_Batch";
        DataProxyRequest request = new DataProxyRequest();
        request.setServiceName(serviceName);
        request.setOperationName(operationName);

        DataProxyResponse response = null;
        try {
            String responseTxt = Request.Post(urlPrefix + "/rest/dataproxy/query")
                    .body(new StringEntity(JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(queryTimeout)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();
            response = JSON.parseObject(responseTxt, DataProxyResponse.class);
        } catch (Exception ex) {
            logger.error(Contexts.getLogPrefix() + "invoke StationToProvince.init fault.", ex);
        }
        int i = 0;
        if (response.getRtnCode() == 0) {
            logger.info("从DataProxy获取了" + response.getResult().size() + "条外卡信息的记录");
            Iterator iterator = response.getResult().values().iterator();

            while (iterator.hasNext()) {
                Map temp = (Map) iterator.next();
                String typeId = (String) temp.get("cardtypeid");
                String rule = (String) temp.get("cardrule");
                String key = typeId + "_" + rule;
                foreignCardInfos.put(key, temp);
            }
        } else {
            logger.error("从DataProxy获取外卡信息的记录失败:" + response.getMessage());
        }
    }

    public static Map getProvinceNames(String cardId, String cardRule) {
        init();
        return foreignCardInfos.get(cardId + "_" + cardRule);
    }
}
