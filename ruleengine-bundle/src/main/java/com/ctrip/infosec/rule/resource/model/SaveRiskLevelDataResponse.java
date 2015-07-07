package com.ctrip.infosec.rule.resource.model;

/**
 * Created by yxjiang on 2015/7/7.
 */
public class SaveRiskLevelDataResponse {
    private Integer RetCode;
    private Long InfoID;

    public Integer getRetCode() {
        return RetCode;
    }

    public void setRetCode(Integer retCode) {
        RetCode = retCode;
    }

    public Long getInfoID() {
        return InfoID;
    }

    public void setInfoID(Long infoID) {
        InfoID = infoID;
    }
}
