package com.ctrip.infosec.rule.resource;

import org.junit.Test;

import java.util.Map;

/**
 * Created by lpxie on 15-7-16.
 */
public class ForeignCardInfoTest
{
    @Test
    public void testGetPro()
    {
        Map singleResult = ForeignCardInfo.getProvinceNames("7","405071");
        System.out.println(singleResult);
    }
}
