package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.utils.Utils;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by lpxie on 15-8-6.
 */
public class GetUidLevelTest
{
    @Test
    public void testGet()
    {
        String result = GetUidLevel.query("wwwwww",true);
        System.out.println("结果："+result);
    }

    @Test
    public void testGetUidLevel()
    {
        Map request = new HashMap();
        request.put("UID","M214355215");

        String urlPrefix = "http://ws.content.members.fws.qa.nt.ctripcorp.com";
        int queryTimeout = 500;

        int threeMonthCount = 0;
        String threeMonthCountResponseTxt = "";
        try
        {
            threeMonthCountResponseTxt = Request.Post(urlPrefix + "/CMB-REPORT-REPORT/json/GetThreeMonthOrderCount")
                    .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(queryTimeout)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
        Map threeMonthCountResponse = Utils.JSON.parseObject(threeMonthCountResponseTxt, Map.class);
        String threeMonthResultCode = threeMonthCountResponse.get("ResultCode").toString();
        if(!threeMonthResultCode.equals("Fail"))
        {
            threeMonthCount = Integer.parseInt(threeMonthCountResponse.get("OrderCount").toString());
        }

        int allCount = 0;
        String allCountResponseTxt = "";
        try
        {
            allCountResponseTxt = Request.Post(urlPrefix + "/CMB-REPORT-REPORT/json/GetDealCountByUid")
                    .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(queryTimeout)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        Map allCountResponse = Utils.JSON.parseObject(allCountResponseTxt, Map.class);
        String allCountResultCode = allCountResponse.get("ResultCode").toString();
        if(!allCountResultCode.equals("Fail"))
        {
            allCount = Integer.parseInt(allCountResponse.get("DealCount").toString());
        }

        int resultCount = allCount - threeMonthCount;
        String userLevel = "";
        if(resultCount>=3)
        {
            userLevel = "REPEAT";
        }else
        {
            userLevel = "NEW";
        }
    }
}
