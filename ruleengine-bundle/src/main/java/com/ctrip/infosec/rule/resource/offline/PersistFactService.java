package com.ctrip.infosec.rule.resource.offline;

import com.ctrip.infosec.common.model.RiskFact;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

/**
 * Created by yxjiang on 2015/7/17.
 */
public class PersistFactService {
    private static final Logger logger = LoggerFactory.getLogger(PersistFactService.class);
    public static final String REMOTE_SAVE_MAP_KEY = "offline4j-persist-remote-map";
    public static final String REMOTE_SAVE_REQID_KEY = "reqid";

    private String saveFactUrl;

    public PersistFactService(String saveFactUrl) {
        this.saveFactUrl = saveFactUrl;
    }

    public void saveFact(RiskFact fact, long reqId){
        try {
            Map<String, Object> data = (Map<String, Object>) fact.ext.get(REMOTE_SAVE_MAP_KEY);
            data.put(REMOTE_SAVE_REQID_KEY, reqId);
            Request.Post(saveFactUrl)
                    .body(new StringEntity(JSON.toJSONString(fact), ContentType.APPLICATION_JSON))
                    .connectTimeout(1000)
                    .socketTimeout(5000)
                    .execute().returnContent().asString();
        }catch (Exception e){
            logger.error("fail to save fact by remote service.", e);
        }
    }
}
