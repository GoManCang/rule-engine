package com.ctrip.infosec.rule.action;
import com.ctrip.infosec.dev.encrypt.CryptoGraphy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by lpxie on 15-5-25.
 */
public class EnAndDecryptionDev
{
    private static Logger logger = LoggerFactory.getLogger(EnAndDecryptionDev.class);

    public static String encryption(String plain)
    {
        CryptoGraphy cryptoGraphy = CryptoGraphy.GetInstance();
        cryptoGraphy.init("https://cscmws.infosec.uat.qa.nt.ctripcorp.com/cscmws/CertificateWS.asmx","ZDYTEST000000001");
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
        cryptoGraphy.init("https://cscmws.infosec.fat.qa.nt.ctripcorp.com/cscmws/CertificateWS.asmx","ZDYTEST000000001");
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
