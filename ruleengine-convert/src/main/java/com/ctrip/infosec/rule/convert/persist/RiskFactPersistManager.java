package com.ctrip.infosec.rule.convert.persist;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class RiskFactPersistManager {
    private final PersistContext ctx = new PersistContext();
    private DbOperationChain operationChain;

    public void persist() throws DbExecuteException {
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
}
