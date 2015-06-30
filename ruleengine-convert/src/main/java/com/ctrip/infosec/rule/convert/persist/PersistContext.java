package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.sars.util.GlobalConfig;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class PersistContext {
    private InheritableSharedMap inheritableShared = new InheritableSharedMap();
    private String table4ReqId = GlobalConfig.getString("reqId.table.name", "InfoSecurity_DealInfo");
    private String column4ReqId = GlobalConfig.getString("reqId.column.name", "ReqID");

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
        Object reqId = getVar(table4ReqId + "." + column4ReqId);
        return reqId == null ? new Long(-1) : Long.valueOf(reqId.toString());
    }

    public Object getVar(String varName) {
        return inheritableShared.getValue(varName);
    }
}
