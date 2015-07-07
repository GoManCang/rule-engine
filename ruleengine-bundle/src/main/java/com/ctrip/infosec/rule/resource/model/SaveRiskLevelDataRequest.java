package com.ctrip.infosec.rule.resource.model;

/**
 * Created by yxjiang on 2015/7/7.
 */
public class SaveRiskLevelDataRequest {
    private Long ResID = 0L;
    private Long ReqID = 0L;
    private Long OrderID = 0L;
    private Integer RiskLevel = 0;
    private String RefNo = "0";

    public Long getResID() {
        return ResID;
    }

    public void setResID(Long resID) {
        ResID = resID;
    }

    public Long getReqID() {
        return ReqID;
    }

    public void setReqID(Long reqID) {
        ReqID = reqID;
    }

    public Long getOrderID() {
        return OrderID;
    }

    public void setOrderID(Long orderID) {
        OrderID = orderID;
    }

    public Integer getRiskLevel() {
        return RiskLevel;
    }

    public void setRiskLevel(Integer riskLevel) {
        RiskLevel = riskLevel;
    }

    public String getRefNo() {
        return RefNo;
    }

    public void setRefNo(String refNo) {
        RefNo = refNo;
    }
}
