package com.ctrip.infosec.rule.model;

import java.util.Map;

/**
 * Created by wgui on 14-12-24.
 */
public class DataProxyRequest {

    private String serviceName;
    private String operationName;
    private Map<String, Object> params;

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getOperationName() {
        return operationName;
    }

    public void setOperationName(String operationName) {
        this.operationName = operationName;
    }

    public Map<String, Object> getParams() {
        return params;
    }

    public void setParams(Map<String, Object> params) {
        this.params = params;
    }

}
