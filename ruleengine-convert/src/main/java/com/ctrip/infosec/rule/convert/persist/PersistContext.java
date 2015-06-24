package com.ctrip.infosec.rule.convert.persist;

import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class PersistContext {
    private Map<String, Object> ctxSharedValues = Maps.newHashMap();
    private InheritableSharedMap inheritableShared = new InheritableSharedMap();

    public void addCtxSharedValues(String prefix, Map<String, Object> sharedValues) {
        if (StringUtils.isBlank(prefix)) {
            ctxSharedValues.putAll(sharedValues);
        } else {
            for (Map.Entry<String, Object> entry : sharedValues.entrySet()) {
                ctxSharedValues.put(prefix + "." + entry.getKey(), entry.getValue());
            }
        }
    }

    public void enterChildEnv(Map<String, Object> sharedValues) {
        inheritableShared.getCurrentMap().putAll(sharedValues);
        inheritableShared.enterChild();
    }

    public void returnFromChild() {
        inheritableShared.returnFromChild();
    }
}
