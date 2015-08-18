package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.Condition;
import com.ctrip.infosec.configs.event.Logical;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/23.
 */
public class DbOperationChain {
    private static final Logger logger = LoggerFactory.getLogger(DbOperationChain.class);
    private DbOperation currentOperation;
    private final List<Condition> conditions;
    private final Logical conditionsLogical;
    private final Map<String, Object> data;
    private DbOperationChain nextOperationChain;
    private DbOperationChain childOperationChain;

    public DbOperationChain(DbOperation operation) {
        this(operation, null, null, null);
    }

    public DbOperationChain(DbOperation operation, List<Condition> conditions, Logical conditionsLogical, Map<String, Object> data) {
        this.currentOperation = operation;
        this.conditions = conditions;
        this.conditionsLogical = conditionsLogical;
        this.data = data;
    }

    public void execute(PersistContext ctx) throws DbExecuteException {
        boolean matched = Configs.match(conditions, conditionsLogical, prepareData(conditions, data, ctx));
        if(matched) {
            try {
                currentOperation.execute(ctx);
                ctx.addCtxSharedValues(currentOperation.getPrefix(), currentOperation.getExposedValue());
            } catch (DbExecuteException e) {
                logger.error(SarsMonitorContext.getLogPrefix() + "operation failed: " + currentOperation, e);
            }
            // 执行子操作
            if (childOperationChain != null) {
                ctx.enterChildEnv();
                childOperationChain.execute(ctx);
                ctx.returnFromChild();
            }
        }
        // 执行下一个操作
        if (nextOperationChain != null) {
            nextOperationChain.execute(ctx);
        }
    }

    private Map<String, Object>  prepareData(List<Condition> conditions, Map<String, Object> data, PersistContext ctx) {
        if(CollectionUtils.isNotEmpty(conditions)){
            for (Condition condition : conditions) {
                String fieldName = condition.getFieldName();
                if(StringUtils.isNotBlank(fieldName)){
                    ArrayList<String> strings = Lists.newArrayList(Splitter.on(':').trimResults().omitEmptyStrings().split(fieldName));

                    if (strings.size() <= 1 || strings.size() > 3) {
                        continue;
                    }
                    if (strings.get(0).equalsIgnoreCase(AbstractRdbmsOperation.CTX)) {
                        String newFieldName = fieldName.replace(".", "$dot$");
                        condition.setFieldName(newFieldName);
                        data.put(newFieldName, ctx.getVar(strings.get(1)));
                    }
                }
            }
        }
        return data;
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

    public void addToTail(DbOperationChain chain) {
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
