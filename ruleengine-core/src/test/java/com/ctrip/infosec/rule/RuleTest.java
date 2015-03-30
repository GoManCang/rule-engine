/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import static com.ctrip.infosec.configs.utils.Utils.JSON;

import com.ctrip.infosec.counter.enums.FlowAccuracy;
import com.ctrip.infosec.counter.model.FlowQueryResponse;
import com.ctrip.infosec.counter.model.PolicyExecuteResponse;
import com.ctrip.infosec.counter.model.PolicyExecuteResult;
import com.ctrip.infosec.rule.resource.Counter;
import static com.ctrip.infosec.rule.util.Emitter.emit;
import com.google.common.collect.ImmutableMap;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Random;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine*.xml"})
public class RuleTest {

    //@Test
    @Ignore
    public void testCP0006021() {
        System.out.println("CP0006021");
        for (int i = 0; i < 11; i++) {
            System.out.println("exec R1: " + i);
            R1();
        }
    }

    void R1() {
        RiskFact $fact = new RiskFact();
        $fact.eventPoint = "CP0006021";
        $fact.ext.put(Constants.key_ruleNo, "CP0006021001");

        $fact.eventBody.put("appID", 1000111);
        $fact.eventBody.put("couponCode", "CCODE111");
        $fact.eventBody.put("couponID", "CID111");
        $fact.eventBody.put("userID", "U111");

        String appId = "" + $fact.eventBody.get("appID");
        String couponCode = "" + $fact.eventBody.get("couponCode");
        String couponId = "" + $fact.eventBody.get("couponID");
        String uid = "" + $fact.eventBody.get("userID");
        
        $fact.results.clear();

        //push to countServer
        Map kvData = ImmutableMap.of("appId", appId, "couponCode", couponCode, "couponId", couponId, "uid", uid);
        PolicyExecuteResponse response = Counter.execute("P0006021001", kvData);
        if ("0".equals(response.getErrorCode())) {
            PolicyExecuteResult policyExecuteResult = response.getPolicyExecuteResult();
            String resultCode = policyExecuteResult.getResultCode();
            String resultMessage = policyExecuteResult.getResultMessage();
            if (!"000".equals(resultCode)) {
                emit($fact, resultCode, resultMessage);
                System.out.println("results: " + JSON.toPrettyJSONString($fact.results));
            }
        }

        //push to countServer
        Counter.push("0006", kvData);
    }

    @Test
    public void testCP0003001()
    {
        System.out.println("CP0003001");
        for(int i=0;i<10;i++)
        {
            System.out.println(i);
            //R2();
            //R3();
            R4();
        }
    }
    //同一个ip对应的相关量
    void R2()
    {
        RiskFact $fact = new RiskFact();
        $fact.eventPoint = "CP0003001";
        $fact.ext.put(Constants.key_ruleNo, "CP0003001");
        //随机生成orderID
        Random random = new Random();
        int randomNum = random.nextInt(10000000);
        $fact.eventBody.put("mobilePhone", randomNum+"");
        $fact.eventBody.put("orderDate", "2015-03-30");
        $fact.eventBody.put("orderID", randomNum+"");
        $fact.eventBody.put("uid", randomNum+"");
        $fact.eventBody.put("userIP", "151.235.656.121");

        String mobilePhone = $fact.eventBody.get("mobilePhone") == null ? "" : $fact.eventBody.get("mobilePhone").toString();
        String orderDate = $fact.eventBody.get("orderDate") == null ? "" : $fact.eventBody.get("orderDate").toString();
        String orderId = $fact.eventBody.get("orderID") == null ? "" : $fact.eventBody.get("orderID").toString();
        String uid = $fact.eventBody.get("uid") == null ? "" : $fact.eventBody.get("uid").toString();
        String userIp = $fact.eventBody.get("userIP") == null ? "" : $fact.eventBody.get("userIP").toString();

        $fact.results.clear();

        //push to countServer
        Map kvData = ImmutableMap.of("mobilePhone", mobilePhone, "orderDate", orderDate, "orderId", orderId, "uid", uid,"userIp",userIp);
        //push to countServer
        Counter.push("0003", kvData);
        //礼遇商城礼品卡支付,一天内，同一IP对应预定量>=5
        BigDecimal count = ((FlowQueryResponse)Counter.queryFlowData("F0003001", "同一IP对应的预定量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count!=null&&count.longValue() >= 5){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一IP对应预定量[" + count.longValue() + "] >= 5");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
        //礼遇商城礼品卡支付,一天内，同一IP对应uid量>=3
        BigDecimal count1 = ((FlowQueryResponse)Counter.queryFlowData("F0003001", "同一IP对应的uid量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count1!=null&&count1.longValue() >= 3){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一IP对应的uid量[" + count1.longValue() + "] >= 3");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
        //礼遇商城礼品卡支付,一天内，同一IP对应联系手机量>=3
        BigDecimal count2 = ((FlowQueryResponse)Counter.queryFlowData("F0003001", "同一IP对应的手机量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count2!=null&&count2.longValue() >= 3){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一IP对应的手机量[" + count2.longValue() + "] >= 3");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
    }
    //同一个uid对应的相关量
    void R3()
    {
        RiskFact $fact = new RiskFact();
        $fact.eventPoint = "CP0003001";
        $fact.ext.put(Constants.key_ruleNo, "CP0003001");
        //随机生成orderID
        Random random = new Random();
        int randomNum = random.nextInt(10000000);
        $fact.eventBody.put("mobilePhone", randomNum+"");
        $fact.eventBody.put("orderDate", "2015-03-30");
        $fact.eventBody.put("orderID", randomNum+"");
        $fact.eventBody.put("uid", "10001");
        $fact.eventBody.put("userIP", randomNum+"");

        String mobilePhone = $fact.eventBody.get("mobilePhone") == null ? "" : $fact.eventBody.get("mobilePhone").toString();
        String orderDate = $fact.eventBody.get("orderDate") == null ? "" : $fact.eventBody.get("orderDate").toString();
        String orderId = $fact.eventBody.get("orderID") == null ? "" : $fact.eventBody.get("orderID").toString();
        String uid = $fact.eventBody.get("uid") == null ? "" : $fact.eventBody.get("uid").toString();
        String userIp = $fact.eventBody.get("userIP") == null ? "" : $fact.eventBody.get("userIP").toString();

        $fact.results.clear();

        //push to countServer
        Map kvData = ImmutableMap.of("mobilePhone", mobilePhone, "orderDate", orderDate, "orderId", orderId, "uid", uid,"userIp",userIp);
        //push to countServer
        Counter.push("0003", kvData);
        //礼遇商城礼品卡支付,一天内，同一IP对应预定量>=5
        BigDecimal count = ((FlowQueryResponse)Counter.queryFlowData("F0003002", "同一uid对应的预定量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count!=null&&count.longValue() >= 8){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一uid对应的预定量[" + count.longValue() + "] >= 8");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
        //礼遇商城礼品卡支付,一天内，同一IP对应uid量>=3
        BigDecimal count1 = ((FlowQueryResponse)Counter.queryFlowData("F0003002", "同一uid对应的ip量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count1!=null&&count1.longValue() >= 3){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一uid对应的ip量[" + count1.longValue() + "] >= 3");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
        //礼遇商城礼品卡支付,一天内，同一IP对应联系手机量>=3
        BigDecimal count2 = ((FlowQueryResponse)Counter.queryFlowData("F0003002", "同一uid对应的手机量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count2!=null&&count2.longValue() >= 3){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一uid对应的手机量[" + count2.longValue() + "] >= 3");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
    }
    //同一手机对应的预定量
    void R4()
    {
        RiskFact $fact = new RiskFact();
        $fact.eventPoint = "CP0003001";
        $fact.ext.put(Constants.key_ruleNo, "CP0003001");
        //随机生成orderID
        Random random = new Random();
        int randomNum = random.nextInt(10000000);
        $fact.eventBody.put("mobilePhone", "13516896542");
        $fact.eventBody.put("orderDate", "2015-03-30");
        $fact.eventBody.put("orderID", randomNum+"");
        $fact.eventBody.put("uid", randomNum+"");
        $fact.eventBody.put("userIP", randomNum+"");

        String mobilePhone = $fact.eventBody.get("mobilePhone") == null ? "" : $fact.eventBody.get("mobilePhone").toString();
        String orderDate = $fact.eventBody.get("orderDate") == null ? "" : $fact.eventBody.get("orderDate").toString();
        String orderId = $fact.eventBody.get("orderID") == null ? "" : $fact.eventBody.get("orderID").toString();
        String uid = $fact.eventBody.get("uid") == null ? "" : $fact.eventBody.get("uid").toString();
        String userIp = $fact.eventBody.get("userIP") == null ? "" : $fact.eventBody.get("userIP").toString();

        $fact.results.clear();

        //push to countServer
        Map kvData = ImmutableMap.of("mobilePhone", mobilePhone, "orderDate", orderDate, "orderId", orderId, "uid", uid,"userIp",userIp);
        //push to countServer
        Counter.push("0003", kvData);
        //礼遇商城礼品卡支付,一天内，同一IP对应预定量>=5
        BigDecimal count = ((FlowQueryResponse)Counter.queryFlowData("F0003003", "同一手机对应的预定量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count!=null&&count.longValue() >= 10){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一手机对应的预定量[" + count.longValue() + "] >= 10");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
        //礼遇商城礼品卡支付,一天内，同一IP对应uid量>=3
        BigDecimal count1 = ((FlowQueryResponse)Counter.queryFlowData("F0003003", "同一手机对应的uid量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count1!=null&&count1.longValue() >= 3){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一手机对应的uid量[" + count1.longValue() + "] >= 3");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
        //礼遇商城礼品卡支付,一天内，同一IP对应联系手机量>=3
        BigDecimal count2 = ((FlowQueryResponse)Counter.queryFlowData("F0003003", "同一手机对应的ip量",
                FlowAccuracy.EveryMin, "0,-1439", kvData)).getFlowData();
        if(count2!=null&&count2.longValue() >= 3){
            emit($fact, 80, "礼遇商城礼品卡支付, 一天内, 同一手机对应的ip量[" + count2.longValue() + "] >= 3");
            System.out.println("results: "+JSON.toPrettyJSONString($fact.results));
        }
    }
}
