package com.ctrip.infosec.rule.convert.persist;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/23.
 */
public interface DbOperation {
    void execute(PersistContext ctx) throws DbExecuteException;
    Map<String, Object> getExposedValue();
}
