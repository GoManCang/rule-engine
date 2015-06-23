package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.configs.event.DataUnitColumnType;

/**
 * Created by jizhao on 2015/6/23.
 */
public class PersistColumnProperties {
    private PersistColumnProperties columnProperties;

    private String expression;

    private DataUnitColumnType columnType;

    private Object value;


    public PersistColumnProperties getColumnProperties() {
        return columnProperties;
    }

    public void setColumnProperties(PersistColumnProperties columnProperties) {
        this.columnProperties = columnProperties;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    public DataUnitColumnType getColumnType() {
        return columnType;
    }

    public void setColumnType(DataUnitColumnType columnType) {
        this.columnType = columnType;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }
}
