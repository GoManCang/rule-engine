package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.utils.Utils;
import com.meidusa.fastjson.JSON;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by lpxie on 15-3-23.
 */
public class CardInTest {

    @Test
    public void testQueryCardInfo() {
        //cardInfoId为30075005这个的可以查询到数据，留这备用
        RiskFact fact = ReadFactFile.getFact("searchCardInfo.json");
        Map params = new HashMap();
        params.put("cardInfoId", fact.eventBody.get("CardInfoID") + "");

        Map map = CardInfo.query("getinfo", params);
        Assert.assertNotNull(map);
        Assert.assertTrue(map.size() > 0);
    }

    @Test
    public void testJSON() {
        String txt = "{\"eventBody\":{\"actualAmount\":100,\"amount\":100,  \"bizType\":    \"80\",\"bookingDate\":\"2015-04-24 22:18:24\",\"discountAmount\":20,\"isHide\":false,\"itemInfos\":[{\"ProductName\":\"上海崇明东平国家森林公园门票\",\"Quantity\":2},{\"ProductName\":\"上海崇明东平国家森林公园门票\",\"Quantity\":0}],\"message_CreateTime\":\"2015-4-29 10:42:30\",\"operateTime\":\"2015-04-29 10:42:25\",\"operators\":\"s42705\",\"orderDescription\":\"已成交\",\"orderId\":1305610599,\"orderStatus\":\"PIAO_COMPLETED\",\"orderVersion\":\"1:2\",\"passengers\":[{\"AgeType\":\"ADU\",\"BirthDate\":\"1900-1-1 0:00:00\",\"CardType\":\"0\",\"Gender\":\"F\",\"Mobile\":\"18621750858\",\"Name\":\"游客  \"}],\"processStatus\":\"133147\",\"remarks\":\"\",\"sourceFromCode\":\"Web\",\"totalAmount\":\"0.00\",\"uid\":\"18601664456\",\"useDateOfFirst\":\"2015-04-26 00:00:00\"},\"eventId\":\"62ca0f80-ee19-11e4-803e-a5f7444d1774\",\"eventPoint\":\"CP0022004\",\"ext\":{\"CHANNEL\":\"CMessage\",\"descTimestamp\":2640604647304},\"finalResult\":{\"riskLevel\":0,\"riskMessage\":\"PASS\"},\"postActions\":{},\"requestReceive\":\"2015-04-29 10:42:32.696\",\"results\":{}}";
//        Map map1 = JSON.parseObject(txt, Map.class);
        Map map2 = Utils.JSON.parseObject(txt, Map.class);

        System.out.println("map2: " + JSON.toJSONString(map2));
    }
}
