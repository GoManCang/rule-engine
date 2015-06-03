package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.sec.userprofile.client.service.BaseService;
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

    static final String urlPrefix = GlobalConfig.getString("DataProxy.REST.URL.Prefix");

    static void check(){
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"DataProxy.REST.URL.Prefix\"配置项.");
    }

    public static List<String> getCountriesByPassportNum(String passPort)
    {
        check();
        try{
            PassportService.setConfigUrl(urlPrefix);
            return  PassportService.getCountries(passPort);
        }catch (Exception exp)
        {
            logger.warn(Contexts.getLogPrefix()+"获取护照信息异常:",exp.getMessage());
            return new ArrayList<String>();
        }
    }
}
