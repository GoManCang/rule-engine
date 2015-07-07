package com.ctrip.infosec.rule.resource.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Created by yxjiang on 2015/7/7.
 */
@XmlRootElement
public class ESBResponse {
    @XmlElement
    private Header Header;
    private SaveRiskLevelDataResponse SaveRiskLevelDataResponse;

    public Header getHeader() {
        return Header;
    }

    public void setHeader(Header Header) {
        this.Header = Header;
    }

    public SaveRiskLevelDataResponse getSaveRiskLevelDataResponse() {
        return SaveRiskLevelDataResponse;
    }

    public void setSaveRiskLevelDataResponse(SaveRiskLevelDataResponse SaveRiskLevelDataResponse) {
        this.SaveRiskLevelDataResponse = SaveRiskLevelDataResponse;
    }
}
