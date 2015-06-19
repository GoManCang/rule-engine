package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.ConfigsDeamon;
import com.ctrip.infosec.configs.Part;
import com.meidusa.fastjson.JSON;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

import java.util.concurrent.TimeUnit;

/**
 * Created by yxjiang on 2015/6/19.
 */
@ContextConfiguration("classpath:spring/configs.xml")
public class RiskFactPersistConfigHolderTest extends AbstractJUnit4SpringContextTests {
    @Test
    @Ignore
    public void testLoadConfig() throws Exception {
        ConfigsDeamon deamon = new ConfigsDeamon();
        deamon.setUrl("http://localhost:8180/rest/loadconfig");
        deamon.setPart(Part.FactPersistConfig);
        deamon.setCallback(new ConvertRuleUpdateCallback());
        deamon.start();
        TimeUnit.SECONDS.sleep(35);
        System.out.println(JSON.toJSONString(RiskFactPersistConfigHolder.localPersistConfigs, true));
        System.out.println(JSON.toJSONString(RiskFactPersistConfigHolder.localDataUnitMetadatas, true));
    }
}