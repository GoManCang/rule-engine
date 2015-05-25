package com.ctrip.infosec.rule.action;

import com.ctrip.infosec.encrypt.CryptoGraphy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by lpxie on 15-5-25.
 */
public class EnAndDecryption
{
    private static Logger logger = LoggerFactory.getLogger(EnAndDecryption.class);

    public static String encryption(String plain)
    {
        CryptoGraphy cryptoGraphy = CryptoGraphy.GetInstance();
        cryptoGraphy.init("https://cscmws.infosec.ctripcorp.com/cscmws/CertificateWS.asmx","UI00000000000131");
        String cypher = null;
        try
        {
            cypher = cryptoGraphy.encrypt(plain);
            return cypher;
        } catch (Exception e)
        {
            logger.warn(plain+"加密异常"+e.getMessage());
        }
        return cypher;
    }

    public static String decryption(String complexText)
    {
        CryptoGraphy cryptoGraphy = CryptoGraphy.GetInstance();
        cryptoGraphy.init("https://cscmws.infosec.ctripcorp.com/cscmws/CertificateWS.asmx","UI00000000000131");
        String txt = "";
        try
        {
            txt = cryptoGraphy.decrypt(complexText);
            return txt;
        } catch (Exception e)
        {
            logger.warn(complexText+"解密异常"+e.getMessage());
        }
        return txt;
    }
}
