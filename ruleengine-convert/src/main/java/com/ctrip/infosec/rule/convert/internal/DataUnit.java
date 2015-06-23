package com.ctrip.infosec.rule.convert.internal;

import com.ctrip.infosec.configs.event.DataUnitDefinition;
import com.ctrip.infosec.configs.event.DataUnitMetadata;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class DataUnit {
    private DataUnitDefinition definition;
    private Object data;

    public DataUnitDefinition getDefinition() {
        return definition;
    }

    public void setDefinition(DataUnitDefinition definition) {
        this.definition = definition;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public DataUnitMetadata getMetadata() {
        return definition.getMetadata();
    }
}
