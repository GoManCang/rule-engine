package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.rule.resource.model.SaveRiskLevelDataRequest;
import com.thoughtworks.xstream.MarshallingStrategy;
import com.thoughtworks.xstream.XStream;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Created by yxjiang on 2015/7/7.
 */
public class RiskLevelDataTest {

    @Test
    public void testSave() throws Exception {
        RiskLevelData.save(0, 0, 0);
    }
}