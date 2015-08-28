package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.meidusa.fastjson.JSON;
import org.apache.commons.lang3.Validate;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by lpxie on 2015/8/24.
 */
public class GiftCardHistoryDetail {
    private static final Logger logger = LoggerFactory.getLogger(GiftCardHistoryDetail.class);
    private static final String urlPrefix = GlobalConfig.getString("GetGiftHistoryDetail.REST.URL.Prefix");
    private static final int queryTimeout = GlobalConfig.getInteger("GetGiftHistoryDetail.query.timeout", 500);
    private static final int defaultPageSize = 100000;
    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"GetGiftHistoryDetail.REST.URL.Prefix\"配置项.");
    }

    public static ArrayList query(String uid,String startTime,String endTime)
    {
        check();
        beforeInvoke();
        ArrayList response = null;
        try
        {
            Map<String,Object> request = new HashMap<>();
            request.put("UID",uid);
            request.put("SourceType","1");
            request.put("TicketCategoryID","0");
            request.put("TransTypeID","0");
            request.put("StartDate",startTime);
            request.put("EndDate",endTime);
            request.put("PageIndex","1");
            request.put("PageSize",defaultPageSize);//默认10万 如果小于这个值就再取剩下的值
            String result = Request.Post(urlPrefix + "/gcaccountws/json/GetGCTransDetailList")
                    .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(queryTimeout)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();

            Map<String,Object> temp = JSON.parseObject(result, Map.class);
            if(temp.get("ResCode").toString().equals("0"))
            {
                String listContent = JSON.toJSONString(temp.get("TransDetailList"));
                response = JSON.parseObject(listContent,ArrayList.class);

                String total = temp.get("TotalCount").toString();
                if(Integer.parseInt(total) > defaultPageSize)
                {
                    int nextPageSize = Integer.parseInt(total);
                    request.put("PageSize",nextPageSize);
                    String nextResult  = Request.Post(urlPrefix + "/gcaccountws/json/GetGCTransDetailList")
                            .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                            .connectTimeout(queryTimeout)
                            .socketTimeout(queryTimeout)
                            .execute().returnContent().asString();
                    Map<String,Object> nextTemp = JSON.parseObject(nextResult, Map.class);
                    if(nextTemp.get("ResCode").toString().equals("0"))
                    {
                        String nextListContent = JSON.toJSONString(nextTemp.get("TransDetailList"));
                        response.clear();
                        response.addAll(JSON.parseObject(nextListContent, ArrayList.class));
                    }
                }
            }
        }catch (Exception ex) {
            response = new ArrayList();
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke GiftCardHistoryDetail.query fault.", ex);
            TraceLogger.traceLog("执行GiftCardHistoryDetail异常: " + ex.toString());
        } finally {
            afterInvoke("GiftCardHistoryDetail.query");
        }
        return response;
    }
}
