package com.ctrip.infosec.rule.model;

import java.util.Map;

/**
 * Created by wgui on 14-12-24.
 */
public class DataProxyResponse {

    /**
     * 0 正确，非0失败
     */
    private int rtnCode;
    /**
     * 错误信息
     */
    private String message;
    /**
     * 正确时，返回结果
     */
    private Map<String, Object> result;

    public int getRtnCode() {
        return rtnCode;
    }

    public void setRtnCode(int rtnCode) {
        this.rtnCode = rtnCode;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Map<String, Object> getResult() {
        return result;
    }

    public void setResult(Map<String, Object> result) {
        this.result = result;
    }

}
