package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.configs.event.DataUnitMetadata;
import com.ctrip.infosec.configs.event.DistributionChannel;

import java.util.Map;

/**
 * Created by jizhao on 2015/6/23.
 */
public class RdbmsInsert implements DbOperation {

    /**
     * 数据分发通道
     */
    private DistributionChannel channel;

    /**
     * key: 数据序列  value： 数据来源和 表达式
     */
    Map<String, PersistColumnProperties> columnPropertiesMap;

    @Override
    public void execute(PersistContext ctx) throws DbExecuteException {

    }

    @Override
    public Map<String, Object> getExposedValue() {
        return null;
    }



}
