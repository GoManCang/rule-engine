package com.ctrip.infosec.rule.convert.persist;

/**
 * Created by jizhao on 2015/6/23.
 */
public class PersistColumnProperties {
    private PersistColumnProperties columnProperties;

    private String expression;


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
}
