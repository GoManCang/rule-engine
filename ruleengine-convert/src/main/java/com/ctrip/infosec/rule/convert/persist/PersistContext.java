package com.ctrip.infosec.rule.convert.persist;

import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class PersistContext {
    private InheritableSharedMap inheritableShared = new InheritableSharedMap();

    public void addCtxSharedValues(String prefix, Map<String, Object> sharedValues) {
        inheritableShared.addSharedValues(prefix, sharedValues);
    }

    public void enterChildEnv() {
        inheritableShared.enterChild();
    }

    public void returnFromChild() {
        inheritableShared.returnFromChild();
    }

    public Long getReqId() {
        Object reqId = getVar("CardRisk_DealInfo.ReqID");
        return reqId == null ? new Long(-1) : Long.valueOf(reqId.toString());
    }

    public Object getVar(String varName) {
        return inheritableShared.getValue(varName);
    }
}
