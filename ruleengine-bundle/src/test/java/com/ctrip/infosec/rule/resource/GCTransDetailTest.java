package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.sec.userprofile.vo.content.response.DataProxyResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by lpxie on 15-8-4.
 */
public class GCTransDetailTest
{
    @Test
    public void testGCTransDetail()
    {
        Map  request = new HashMap();
        request.put("SourceType","1");
        request.put("UID","www");
        request.put("TicketCategoryID","");
        request.put("TransTypeID","");
       // request.put("StartDate","");
       // request.put("EndDate","");
        request.put("PageSize","1");
        request.put("PageIndex","1");
        String responseTxt = "";
        String urlPrefix = "http://ws.account.giftcard.fws.qa.nt.ctripcorp.com";
        int queryTimeout = 500;
        try
        {
            responseTxt = Request.Post(urlPrefix + "/gcaccountws/json/GetGCTransDetailList")
                    .body(new StringEntity(Utils.JSON.toJSONString(request), ContentType.APPLICATION_JSON))
                    .connectTimeout(queryTimeout)
                    .socketTimeout(queryTimeout)
                    .execute().returnContent().asString();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
        Map response = Utils.JSON.parseObject(responseTxt, Map.class);

    }
}
