package com.ctrip.infosec.rule.convert.persist;

import com.google.common.collect.Maps;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class RiskFactPersistManager {
    private final PersistContext ctx = new PersistContext();
    private DbOperationChain operationChain;

    public PersistContext persist(Integer riskLevel, String resultRemark) throws DbExecuteException {
        Map<String, Object> rootSharedValues = Maps.newHashMap();
        rootSharedValues.put("riskLevel", riskLevel);
        rootSharedValues.put("riskRemark", resultRemark);
        ctx.addCtxSharedValues(null, rootSharedValues);
        if (operationChain != null) {
            operationChain.execute(ctx);
        }
        return ctx;
    }

    public void setOperationChain(DbOperationChain operationChain) {
        this.operationChain = operationChain;
    }

    @Override
    public String toString() {
        return "RiskFactPersistManager{" +
                "ctx=" + ctx +
                ", operationChain=" + operationChain +
                '}';
    }

    public long getGeneratedReqId() {
        Long reqId = ctx.getReqId();
        if (reqId != null) {
            return reqId.longValue();
        }
        return -1;
    }

    public long getOrderId() {
        // 硬编码的值，考虑以后采用页面配置方式
        return getLong("InfoSecurity_MainInfo.OrderId");
    }

    public Object getValue(String name) {
        return ctx.getVar(name);
    }

    public Long getLong(String name) {
        Object val = getValue(name);
        if (val instanceof Long) {
            return (Long) val;
        }
        if (val == null) {
            return 0L;
        } else {
            try {
                return Long.valueOf(val.toString());
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
    }

    public String getString(String name) {
        Object val = getValue(name);
        if (val instanceof String) {
            return (String) val;
        }
        if (val == null) {
            return null;
        } else {
            return val.toString();
        }
    }

    public Integer getInteger(String name) {
        Object val = getValue(name);
        if (val instanceof Integer) {
            return (Integer) val;
        }
        if (val == null) {
            return 0;
        } else {
            try {
                return Integer.valueOf(val.toString());
            } catch (NumberFormatException e) {
                return 0;
            }
        }
    }
}
