package com.ctrip.infosec.rule.convert.persist;

import java.util.Map;

/**
 * Created by yxjiang on 2015/6/23.
 */
public class DbOperationChain {
    private DbOperation currentOperation;
    private DbOperationChain nextOperationChain;
    private DbOperationChain childOperationChain;

    public DbOperationChain(DbOperation operation) {
        this.currentOperation = operation;
    }

    public void execute(PersistContext ctx) throws DbExecuteException {
        currentOperation.execute(ctx);
        ctx.addCtxSharedValues(currentOperation.getPrefix(), currentOperation.getExposedValue());
        // 执行子操作
        if (childOperationChain != null) {
            ctx.enterChildEnv();
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

    public void addToChildOperationChain(DbOperationChain chain) {
        if (this.childOperationChain == null) {
            this.childOperationChain = chain;
        } else {
            this.childOperationChain.addToTail(chain);
        }
    }

    private void addToTail(DbOperationChain chain) {
        if (chain == null) {
            return;
        }
        DbOperationChain last = this;
        while (last.nextOperationChain != null){
            last = last.nextOperationChain;
        }
        last.nextOperationChain = chain;
    }

    @Override
    public String toString() {
        return "DbOperationChain{" +
                "currentOperation=" + currentOperation +
                ", nextOperationChain=" + nextOperationChain +
                ", childOperationChain=" + childOperationChain +
                '}';
    }
}
