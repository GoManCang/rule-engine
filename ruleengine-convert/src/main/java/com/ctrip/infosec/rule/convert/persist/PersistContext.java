package com.ctrip.infosec.rule.convert.persist;

import com.google.common.collect.Maps;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class PersistContext {
    private Map<String, Object> ctxSharedValues = Maps.newHashMap();
    private InheritableSharedMap inheritableShared = new InheritableSharedMap();

    public void addCtxSharedValues(Map<String, Object> ctxSharedValues) {
        ctxSharedValues.putAll(ctxSharedValues);
    }

    public void enterChildEnv(Map<String, Object> sharedValues) {
        inheritableShared.getCurrentMap().putAll(sharedValues);
        inheritableShared.enterChild();
    }

    public void returnFromChild() {
        inheritableShared.returnFromChild();
    }
}
