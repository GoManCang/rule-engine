/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import org.junit.Test;

/**
 *
 * @author zhengby
 */
public class CryptoTest {

    @Test
    public void testDecryptDev() {
        //加密
//        System.out.println(Crypto.encrypt("3214566987345343jgfjf"));
        //解密
        //fat   CTRP7D4A9037D45BB0B8B3297DC607D3281D
        //uat  CTRPA13F75FE8D370C6862BEB376016607BB
        
        String e = Crypto.encrypt("zhengby");
        System.out.println("encrypt: " + e);

        System.out.println(Crypto.decrypt(e));
    }

    @Test
    public void testDecryptProd() {
        //加密
        System.out.println(Crypto.decrypt("3214566987"));
        //解密
        //System.out.println(EnAndDecryption.decryption("CTRP7D4A9037D45BB0B8B3297DC607D3281D"));
    }
}
