package com.ctrip.infosec.rule.convert.persist;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/23.
 */
public class DbOperationChain {
    private DbOperation currentOperation;
    private DbOperationChain nextOperationChain;
    private DbOperationChain childOperationChain;

    public DbOperationChain(DbOperation operation){
        this.currentOperation = operation;
    }

    public void execute(PersistContext ctx) throws DbExecuteException {
        currentOperation.execute(ctx);
        Map<String, Object> exposedValue = currentOperation.getExposedValue();
        ctx.addCtxSharedValues(exposedValue);
        // 执行子操作
        if (childOperationChain != null) {
            ctx.enterChildEnv(exposedValue);
            childOperationChain.execute(ctx);
            ctx.returnFromChild();
        }
        // 执行下一个操作
        if (nextOperationChain != null) {
            nextOperationChain.execute(ctx);
        }
    }

    public void setNextOperationChain(DbOperationChain nextOperationChain) {
        this.nextOperationChain = nextOperationChain;
    }

    public void setChildOperationChain(DbOperationChain childOperationChain) {
        this.childOperationChain = childOperationChain;
    }
}
