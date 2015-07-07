package com.ctrip.infosec.rule.convert.persist;

import com.google.common.collect.Maps;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class RiskFactPersistManager {
    private final PersistContext ctx = new PersistContext();
    private DbOperationChain operationChain;

    public void persist(Integer riskLevel, String resultRemark) throws DbExecuteException {
        Map<String, Object> rootSharedValues = Maps.newHashMap();
        rootSharedValues.put("riskLevel", riskLevel);
        rootSharedValues.put("riskRemark", resultRemark);
        ctx.addCtxSharedValues(null, rootSharedValues);
        if (operationChain != null) {
            operationChain.execute(ctx);
        }
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
        Object orderId = ctx.getVar("InfoSecurity_MainInfo.OrderId");
        if (orderId instanceof Long) {
            return (Long)orderId;
        }
        if (orderId == null) {
            return 0;
        } else {
            try {
                return Long.valueOf(orderId.toString());
            }catch (NumberFormatException e){
                return 0;
            }
        }
    }
}
