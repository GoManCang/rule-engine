/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 加解密组件
 *
 * @author zhengby
 */
public class Crypto {

    private static Logger logger = LoggerFactory.getLogger(Crypto.class);
    /**
     *
     */
    static final String cscmUrl = GlobalConfig.getString("CryptoGraphy.cscmUrl");
    static final String sslcode = GlobalConfig.getString("CryptoGraphy.sslcode");
    static final String env = GlobalConfig.getString("CryptoGraphy.dependency.env");

    static final String DEV = "DEV";
    static final String PROD = "PROD";
    static com.ctrip.infosec.encrypt.CryptoGraphy cryptoGraphyProd = null;
    static com.ctrip.infosec.dev.encrypt.CryptoGraphy cryptoGraphyDev = null;
    static
    {
        if(PROD.equals(env))
        {
            logger.info("初始化生产环境的加解密实例");
            cryptoGraphyProd = com.ctrip.infosec.encrypt.CryptoGraphy.GetInstance();
            cryptoGraphyProd.init(cscmUrl, sslcode);
        }else
        {
            logger.info("初始化测试环境的加解密实例");
            cryptoGraphyDev = com.ctrip.infosec.dev.encrypt.CryptoGraphy.GetInstance();
            cryptoGraphyDev.init(cscmUrl, sslcode);
        }
    }
    static void check() {
        Validate.notEmpty(cscmUrl, "在GlobalConfig.properties里没有找到\"CryptoGraphy.cscmUrl\"配置项.");
        Validate.notEmpty(sslcode, "在GlobalConfig.properties里没有找到\"CryptoGraphy.sslcode\"配置项.");
        Validate.notEmpty(env, "在GlobalConfig.properties里没有找到\"CryptoGraphy.dependency.env\"配置项.");
    }

    public static String encrypt(String plain) {
        check();
        beforeInvoke();
        String cypher = null;
        try {
            if (PROD.equals(env)) {
                cypher = cryptoGraphyProd.encrypt(plain);
            } else {
                cypher = cryptoGraphyDev.encrypt(plain);
            }
        } catch (Exception ex) {
            fault();
            logger.warn(Contexts.getLogPrefix() + "encrypt fault. plain=" + plain, ex);
        } finally {
            afterInvoke("Crypto.encrypt");
        }
        return cypher;
    }

    public static String decrypt(String complexText) {
        check();
        beforeInvoke();
        String txt = null;
        try {
            if (PROD.equals(env)) {
                txt = cryptoGraphyProd.decrypt(complexText);
            } else {
                txt = cryptoGraphyDev.decrypt(complexText);
            }
        } catch (Exception ex) {
            fault();
            logger.warn(Contexts.getLogPrefix() + "decrypt fault. complexText=" + complexText, ex);
        } finally {
            afterInvoke("Crypto.decrypt");
        }
        return txt;
    }
}
