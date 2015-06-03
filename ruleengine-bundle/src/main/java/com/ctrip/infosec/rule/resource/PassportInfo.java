package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.sec.userprofile.client.service.PassportService;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static com.ctrip.infosec.configs.utils.Utils.JSON;

/**
 * 根据护照号码查询所在国家集合
 * Created by lpxie on 15-6-3.
 */
public class PassportInfo
{
    private static Logger logger = LoggerFactory.getLogger(PassportInfo.class);

    public static List<String> getCountriesByPassportNum(String passPort)
    {
        try{
            return  PassportService.getCountries(passPort);
        }catch (Exception exp)
        {
            logger.warn(Contexts.getLogPrefix()+"获取护照信息异常:",exp.getMessage());
            return new ArrayList<String>();
        }
    }
}
