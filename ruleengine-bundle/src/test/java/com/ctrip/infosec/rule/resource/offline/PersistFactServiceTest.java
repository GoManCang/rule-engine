package com.ctrip.infosec.rule.resource.offline;

import com.ctrip.infosec.common.model.RiskFact;
import com.meidusa.fastjson.JSON;
import org.junit.Ignore;
import org.junit.Test;

import java.util.HashMap;

/**
 * Created by yxjiang on 2015/7/17.
 */
public class PersistFactServiceTest {
    @Test
    @Ignore
    public void testSave() {
        String data = "{\"merchantid\":\"1558\",\"orderid\":0,\"ordertype\":18,\"paymentinfo\":{\"paymentinfolist\":[{\"cardinfolist\":[{\"cardinfoid\":\"12358\",\"infoid\":1235}],\"payment\":{\"amount\":124.0,\"prepaytype\":\"Tmony\"}},{\"cardinfolist\":[{\"cardinfoid\":\"1258\",\"infoid\":66}],\"payment\":{\"amount\":78.0,\"prepaytype\":\"CCARD\"}}]},\"productinfo\":{\"contactinfo\":{\"contactemail\":\"lxyy@163.com\",\"contactname\":\"ContactName\",\"contacttel\":\"8117755\",\"mobilephone\":\"13701488549\",\"mobilephonecity\":\"常州\",\"mobilephoneprovince\":\"江苏\",\"sendtickeraddr\":\"SendTickerAddr\"},\"corporation\":{\"canaccountpay\":\"bbb\",\"companytype\":\"T\",\"corp_paytype\":\"abc\",\"corpid\":\"12558\"},\"devoteinfoviewbyjifen\":{},\"ipinfo\":{\"useripvalue\":3232235777},\"maininfo\":{\"amount\":1225.0,\"checktype\":1,\"corporationid\":\"12558\",\"isonline\":\"T\",\"merchantid\":\"1558\",\"merchantorderid\":\"9885375\",\"orderdate\":\"2014-08-11 11:22:05.094\",\"orderid\":0,\"ordertype\":18,\"refno\":\"12255\",\"serverfrom\":\"Serverfrom\",\"subordertype\":0},\"railinfolist\":[{\"rail\":{\"acity\":\"60\",\"dcity\":\"40\",\"departuredate\":\"2014-08-11 11:22:05.096\",\"fromstationname\":\"FromStationName\",\"merchantorderid\":\"9885375\",\"seatclass\":\"40\",\"trainno\":\"11\"},\"user\":{\"acity\":\"60\",\"dcity\":\"40\",\"departuredate\":\"2014-08-11 11:22:05.096\",\"fromstationname\":\"FromStationName\",\"insurancetype\":\"33\",\"passengeridcode\":\"66\",\"passengeridtype\":\"22\",\"passengername\":\"PassengerName1\",\"seatclass\":\"40\",\"trainno\":\"11\"}},{\"rail\":{\"acity\":\"10\",\"dcity\":\"20\",\"departuredate\":\"2014-08-11 11:22:05.096\",\"fromstationname\":\"FromStationName2\",\"merchantorderid\":\"9885375\",\"seatclass\":\"77\",\"trainno\":\"22\"},\"user\":{\"acity\":\"10\",\"dcity\":\"20\",\"departuredate\":\"2014-08-11 11:22:05.096\",\"fromstationname\":\"FromStationName2\",\"insurancetype\":\"44\",\"passengeridcode\":\"33\",\"passengeridtype\":\"66\",\"passengername\":\"88\",\"seatclass\":\"77\",\"trainno\":\"22\"}}],\"userinfo\":{\"bindedemail\":\"test@163.com\",\"bindedmobilephone\":\"13616667784\",\"city\":\"2\",\"cuscharacter\":\"REPEAT\",\"experience\":\"-1649312265\",\"relatedemail\":\"hj_liu@ctrip.com\",\"relatedemobilephone\":\"13355555555\",\"signupdate\":\"2008-02-20T13:25:32\",\"sourceid\":\"8\",\"uid\":\"test111111\",\"useripadd\":\"192.168.1.1\",\"userpassword\":\"E10ADC3949BA59ABBE56E057F20F883E\",\"vipgrade\":\"20\"}},\"risklevel\":75,\"subordertype\":0}";
        RiskFact fact = new RiskFact();
        HashMap dataMap = JSON.parseObject(data, HashMap.class);
        fact.ext = new HashMap<>();
        fact.ext.put("offline4j-persist-remote-map", dataMap);
        new PersistFactService("http://10.2.56.170:8080/flowtable4j/rest/saveData4Offline").saveFact(fact,123456789);
    }
}