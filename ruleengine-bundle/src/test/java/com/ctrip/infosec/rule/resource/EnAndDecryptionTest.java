package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.action.EnAndDecryption;
import com.ctrip.infosec.rule.action.EnAndDecryptionDev;
import org.junit.Test;

/**
 * Created by lpxie on 15-5-25.
 */
public class EnAndDecryptionTest
{
    @Test
    public void testEnAndDecryptionDev()
    {
        //加密
        //System.out.println(EnAndDecryptionDev.encryption("3214566987"));
        //解密
        System.out.println(EnAndDecryptionDev.decryption("CTRP7D4A9037D45BB0B8B3297DC607D3281D"));
    }

    @Test
    public void testEnAndDecryption()
    {
        //加密
        System.out.println(EnAndDecryption.encryption("3214566987"));
        //解密
        //System.out.println(EnAndDecryption.decryption("CTRP7D4A9037D45BB0B8B3297DC607D3281D"));
    }
}
