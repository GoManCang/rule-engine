package com.ctrip.infosec.rule.resource;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/**
 * Created by lpxie on 15-6-3.
 */
public class PassportInfoTest
{
    @Test
    public void testGetPassportInfo()
    {
        String passport = "E3415354";
        List<String> results = PassportInfo.getCountriesByPassportNum(passport);
        Assert.assertNotNull(results);
    }
}
