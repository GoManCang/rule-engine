package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.model.RiskFact;
import org.drools.marshalling.impl.ProtobufMessages;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Created by lpxie on 15-3-23.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/ruleengine*.xml"})
public class RedisExecutorServiceTest
{
    @Autowired
    private EventDataMergeService redisExecutorService;

    @Test
    public void testMerge()
    {
        String beMerged = "beMerged.json";
        String mergedTo = "MergedTo.json";
        RiskFact beMergedFact = ReadFactFile.getFact(beMerged);
        RiskFact mergedToFact = ReadFactFile.getFact(mergedTo);
        redisExecutorService.executeRedisOption(beMergedFact);
        Assert.assertFalse(mergedToFact.eventBody.containsKey("currency"));//the 'currency is to be merged '
        redisExecutorService.executeRedisOption(mergedToFact);
        Assert.assertTrue(mergedToFact.eventBody.containsKey("currency"));
    }
}
