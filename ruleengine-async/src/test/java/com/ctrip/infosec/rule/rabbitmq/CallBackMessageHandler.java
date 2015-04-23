package com.ctrip.infosec.rule.rabbitmq;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.common.model.RiskResult;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import org.springframework.beans.factory.annotation.Autowired;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

/**
 * Created by lpxie on 15-4-9.
 */
public class CallBackMessageHandler
{
    public void handleMessage(Object message) throws Exception {
        RiskFact fact = null;
        String factTxt = null;
        try {
            if (message instanceof byte[]) {
                factTxt = new String((byte[]) message, Constants.defaultCharset);
            } else if (message instanceof String) {
                factTxt = (String) message;
            } else {
                throw new IllegalArgumentException("消息格式只支持\"String\"或\"byte[]\"");
            }
            System.out.println(factTxt);

        } catch (Throwable ex) {
//            logger.error(Contexts.getLogPrefix() + "invoke query exception.", ex);
        }
    }
}
