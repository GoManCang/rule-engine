package com.ctrip.infosec.rule.convert.persist;

import com.google.common.collect.Maps;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/24.
 */
public class RdbmsEmptyOperation implements DbOperation {
    @Override
    public void execute(PersistContext ctx) throws DbExecuteException {

    }

    @Override
    public Map<String, Object> getExposedValue() {
        return Maps.newHashMap();
    }

    @Override
    public String getPrefix() {
        return null;
    }
}
