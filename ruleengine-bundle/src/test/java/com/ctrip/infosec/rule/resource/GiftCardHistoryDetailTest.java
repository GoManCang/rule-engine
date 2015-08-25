package com.ctrip.infosec.rule.resource;

import org.junit.Test;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Created by lpxie on 2015/8/24.
 */
public class GiftCardHistoryDetailTest {
    @Test
    public void test()
    {
   /*     SimpleDateFormat s = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        Date date = new Date();*/

        List result = GiftCardHistoryDetail.query("wwwwww", "2000-01-01", "2015-08-08");
        return;
    }
}
