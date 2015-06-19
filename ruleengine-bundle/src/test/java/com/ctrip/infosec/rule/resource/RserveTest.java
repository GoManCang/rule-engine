package com.ctrip.infosec.rule.resource;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Created by lpxie on 15-6-19.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class RserveTest
{
    @Test
    public void testR()
    {
        //System.out.print(RService.getScore("logistic.predict(c(1,'Active', 2,'offline','huadong',1,'NEW','new_user',1,1,'low','huadong'))"));
        for(int i=0;i<100000;i++)
        {
            //new Thread(){
//                public void run()
                {
                    System.out.println( RService.getScore("logistic.predict(c(1,'Active', 2,'offline','huadong',1,'NEW','new_user',1,1,'low','huadong'))"));
                }
//            }.start();
        }
    }
}
