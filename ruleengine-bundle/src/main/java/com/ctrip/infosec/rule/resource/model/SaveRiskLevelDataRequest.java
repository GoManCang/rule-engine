package com.ctrip.infosec.rule.resource.model;

import java.util.Date;

/**
 * Created by yxjiang on 2015/7/7.
 */
public class SaveRiskLevelDataRequest {
    private Long ResID = 0L;
    private Long ReqID = 0L;
    private Long OrderID = 0L;
    private Integer RiskLevel = 0;
    private String RefNo = "0";
    private Date CreateDate = new Date();
    private Date LastDate = new Date();
    private String Remark = "";
    private Integer OrderType = null;
    private Integer OriginalRiskLevel = null;
    private String Dealed = "F";
    private Integer InfoID = null;
    private String IsForigenCard = null;
    private Integer CardInfoID = null;
    private String Status = null;

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

    public Date getCreateDate() {
        return CreateDate;
    }

    public void setCreateDate(Date createDate) {
        CreateDate = createDate;
    }

    public Date getLastDate() {
        return LastDate;
    }

    public void setLastDate(Date lastDate) {
        LastDate = lastDate;
    }

    public String getRemark() {
        return Remark;
    }

    public void setRemark(String remark) {
        Remark = remark;
    }

    public Integer getOrderType() {
        return OrderType;
    }

    public void setOrderType(Integer orderType) {
        OrderType = orderType;
    }

    public Integer getOriginalRiskLevel() {
        return OriginalRiskLevel;
    }

    public void setOriginalRiskLevel(Integer originalRiskLevel) {
        OriginalRiskLevel = originalRiskLevel;
    }

    public String getDealed() {
        return Dealed;
    }

    public void setDealed(String dealed) {
        Dealed = dealed;
    }

    public Integer getInfoID() {
        return InfoID;
    }

    public void setInfoID(Integer infoID) {
        InfoID = infoID;
    }

    public String getIsForigenCard() {
        return IsForigenCard;
    }

    public void setIsForigenCard(String isForigenCard) {
        IsForigenCard = isForigenCard;
    }

    public Integer getCardInfoID() {
        return CardInfoID;
    }

    public void setCardInfoID(Integer cardInfoID) {
        CardInfoID = cardInfoID;
    }

    public String getStatus() {
        return Status;
    }

    public void setStatus(String status) {
        Status = status;
    }
}
