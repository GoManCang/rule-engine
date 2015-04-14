/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

/**
 *
 * @author zhengby
 */
public class PreActionParam {

    public static final String FIELD = "FIELD";
    public static final String TEXT = "TEXT";

    private String paramName;
    private String paramType;

    public PreActionParam() {
    }

    public PreActionParam(String paramName, String paramType) {
        this.paramName = paramName;
        this.paramType = paramType;
    }

    public String getParamName() {
        return paramName;
    }

    public void setParamName(String paramName) {
        this.paramName = paramName;
    }

    public String getParamType() {
        return paramType;
    }

    public void setParamType(String paramType) {
        this.paramType = paramType;
    }

}
