package com.ctrip.infosec.rule.rest;

import com.ctrip.infosec.common.model.RiskFact;
import org.apache.commons.io.IOUtils;

import java.io.IOException;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

/**
 * Created by lpxie on 15-3-23.
 */
public class ReadFactFile
{
    public static RiskFact getFact(String jsonPath)
    {
        String str = null;
        try
        {
            str = IOUtils.toString(ReadFactFile.class.getClassLoader().getResourceAsStream(jsonPath), "utf-8");
        } catch (IOException e)
        {
            e.printStackTrace();
        }
        RiskFact fact = JSON.parseObject(str,RiskFact.class);
        return fact;
    }
}
