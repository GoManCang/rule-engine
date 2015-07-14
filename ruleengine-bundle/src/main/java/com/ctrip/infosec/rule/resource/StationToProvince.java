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

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import static com.ctrip.infosec.configs.utils.Utils.JSON;

/**
 * 根据火车站名称得到省的名称
 * 返回的是当前火车站都有的省名称，是唯一的
 * Created by lpxie on 15-7-14.
 */
public class StationToProvince
{

    private static final Logger logger = LoggerFactory.getLogger(StationToProvince.class);

    private static Map<String, String> stationAndPro = new HashMap<>();

    private static boolean isInit = false;

    static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");

    private static final int queryTimeout = GlobalConfig.getInteger("DataProxy.query.timeout", 5000);

    static Lock lock = new ReentrantLock();

    private static void init()
    {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.REST.URL.Prefix\"配置项.");
        if(!isInit)
        {
            lock.lock();
            try{
                getData();
                isInit = true;
            }catch (Exception exp)
            {
                logger.warn("从DataProxy获取城市中文名和省对应的记录异常:"+exp.getMessage());
            }finally
            {
                lock.unlock();
            }
        }
    }

    private static void getData()
    {
        beforeInvoke();
        String serviceName = "ConvertService";
        String operationName = "getProvinceNameByStationName_Batch";
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
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke StationToProvince.init fault.", ex);
        } finally {
            afterInvoke("StationToProvince.init");
        }
        int i = 0;
        if(response.getRtnCode() == 0)
        {
            logger.info("从DataProxy获取了"+response.getResult().size()+"条火车站名称和省对应的记录");
            Iterator iterator = response.getResult().values().iterator();

            while(iterator.hasNext())
            {
                Map temp = (Map)iterator.next();
                stationAndPro.put(temp.get("stationname").toString(),temp.get("provincename").toString());
            }
        }else
        {
            logger.error("从DataProxy获取城市火车站名称和省对应的记录失败:" + response.getMessage());
        }
    }

    public static String getProvinceNames(String stationName)
    {
        init();
        return stationAndPro.get(stationName);
    }
}
