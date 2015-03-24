package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.bdp.agent.BDPAgent;
import com.ctrip.infosec.bdp.agent.ser.JsonSerImpl;
import com.ctrip.infosec.bdp.agent.slog.SLog;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.util.MonitorAgent;
import com.ctrip.infosec.sars.util.GlobalConfig;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

/**
 * Created by lpxie on 15-3-24.
 */
public class SlogAgent extends MonitorAgent
{
    private static Logger logger = LoggerFactory.getLogger(SlogAgent.class);
    private static String appId = GlobalConfig.getString("appId");
    private static String slogIp = GlobalConfig.getString("SLog.Ip");
    private static BDPAgent<SLog> agent = null;
    static{
        Validate.notEmpty(appId, "在GlobalConfig.properties里没有找到\"appId\"配置项.");
        Validate.notEmpty(slogIp, "在GlobalConfig.properties里没有找到\"SLog.Ip\"配置项.");
        agent = BDPAgent.createLogAgentForBDP(appId, slogIp, JsonSerImpl.getInstance());
    }

    /*
    添加功能把数据发送到大安
     */
    public static void sendToSLog(int logType,String sourceFrom,String subSourceFrom,String sceneType,String uid,String userIp,String clientIp,RiskFact fact)
    {
        beforeInvoke();
        try{
            List<Map<String, String>> msg = new ArrayList<Map<String, String>>();
            msg.add(changeDataForm(fact));
            SLog slog = SLog.createSLog(appId, logType, sourceFrom, subSourceFrom, sceneType, uid, userIp, clientIp, msg);
            agent.sendMessage(slog);
        }catch (Exception exp)
        {
            fault();
            logger.warn(Contexts.getLogPrefix() + "invoke SlogAgent.sendToSLog fault.", exp);
        }finally
        {
            afterInvoke("SlogAgent.sendToSLog");
        }
    }

    public static void sendToSLog(int logType,String sourceFrom,String subSourceFrom,String sceneType,String uid,String userIp,String clientIp,Map map)
    {
        beforeInvoke();
        try{
            List<Map<String, String>> msg = new ArrayList<Map<String, String>>();
            msg.add(map);
            SLog slog = SLog.createSLog(appId, logType, sourceFrom, subSourceFrom, sceneType, uid, userIp, clientIp, msg);
            agent.sendMessage(slog);
        }catch (Exception exp)
        {
            fault();
            logger.warn(Contexts.getLogPrefix() + "invoke SlogAgent.sendToSLog fault.", exp);
        }finally
        {
            afterInvoke("SlogAgent.sendToSLog");
        }
    }

    public static Map<String, String> changeDataForm(RiskFact fact)
    {
        Map<String, String> item = new HashMap<String, String>();
        Iterator iterator = fact.eventBody.keySet().iterator();
        while(iterator.hasNext())
        {
            String key = (String)iterator.next();
            Object object = fact.eventBody.get(key);
            //数据是从map 到 list 到 map
            if(object instanceof List)
            {
                item.put(key,JSON.toJSONString(object));
            }else if(object instanceof Map)
            {
                item.put(key,JSON.toJSONString(object));
            }else
            {
                item.put(key,object+"");
            }
        }
        return item;
    }
}
