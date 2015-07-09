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
 * Created by lpxie on 15-7-7.
 */
public class CityToProvince
{
    private static final Logger logger = LoggerFactory.getLogger(CityToProvince.class);

    private static Map<String, List> cityAndPro = new HashMap<>();

    private static boolean isInit = false;

    static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");

    private static final int queryTimeout = GlobalConfig.getInteger("DataProxy.query.timeout", 10000);

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
        String operationName = "getCityNameByCityId_Batch";
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
            logger.error(Contexts.getLogPrefix() + "invoke CityToProvince.init fault.", ex);
        } finally {
            afterInvoke("CityToProvince.init");
        }
        int i = 0;
        if(response.getRtnCode() == 0)
        {
            logger.info("从DataProxy获取了"+response.getResult().size()+"条城市中文名和省对应的记录");
            Iterator iterator = response.getResult().values().iterator();

            while(iterator.hasNext())
            {
                Map temp = (Map)iterator.next();
                if(cityAndPro.containsKey(temp.get("cityName").toString()))
                {
                     cityAndPro.get(temp.get("cityName").toString()).add(temp.get("provinceName").toString());
                     //logger.info(temp.get("cityName").toString());
                     i++;
                }else
                {
                    List list = new ArrayList();
                    list.add(temp.get("provinceName").toString());
                    cityAndPro.put(temp.get("cityName").toString(),list);
                }

            }
        }else
        {
            logger.error("从DataProxy获取城市中午名称和省对应的记录失败:" + response.getMessage());
        }
    }

    public static List<String> getProvinceNames(String cityName)
    {
        init();
        return cityAndPro.get(cityName);
    }
}
