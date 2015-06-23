package com.ctrip.infosec.rule.convert.persist;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class RiskFactPersistManager {
    private final PersistContext ctx = new PersistContext();
    private DbOperationChain operationChain;

    public void persist() throws DbExecuteException {
        operationChain.execute(ctx);
    }

    public void setOperationChain(DbOperationChain operationChain) {
        this.operationChain = operationChain;
    }
}
