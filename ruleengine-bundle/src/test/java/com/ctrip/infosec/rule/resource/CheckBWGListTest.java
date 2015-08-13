package com.ctrip.infosec.rule.resource;

import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by lpxie on 15-8-12.
 */
public class CheckBWGListTest
{
    @Test
    public void testQueryBWGList()
    {
        Map params = new HashMap<>();
        Map eventBody = new HashMap();
        eventBody.put("uid","www");
        params.put("eventBody",eventBody);
        ArrayList result = CheckBWGList.query(params);
    }
}
