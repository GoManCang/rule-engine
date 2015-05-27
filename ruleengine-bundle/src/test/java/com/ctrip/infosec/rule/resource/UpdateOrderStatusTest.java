package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.action.UpdateOrderStatus;
import com.meidusa.fastjson.JSON;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by lpxie on 15-4-20.
 */
public class UpdateOrderStatusTest
{
    @Test
    public void testUpdateOrderStatus()
    {
        Map<String ,Object> params = new HashMap();
        params.put("OrderID","123");
        params.put("OrderType","1");
        params.put("OrderStatus","123");
        params.put("MerchantOrderID","123");

        /*params.put("OrderTime","2015-04-16T16:09:39.95..64416+08:00");
        Map resutl = UpdateOrderStatus.updateStatus("123","1","123","123","2855-08-16T16:09:39.9564416+08:00");
*/

        params.put("OrderTime","2015-04-16T16:09:39.9564416+08:00");
        Map resutl = UpdateOrderStatus.updateOrderStatus(params);

        System.out.println(JSON.toJSONString(resutl));
    }
}
