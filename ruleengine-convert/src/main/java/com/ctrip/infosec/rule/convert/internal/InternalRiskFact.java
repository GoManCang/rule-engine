package com.ctrip.infosec.rule.convert.internal;

import java.util.List;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class InternalRiskFact {
    private String eventPoint;
    private String eventId;
    private String appId;
    private List<DataUnit> dataUnits;

    public String getEventPoint() {
        return eventPoint;
    }

    public void setEventPoint(String eventPoint) {
        this.eventPoint = eventPoint;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public String getAppId() {
        return appId;
    }

    public void setAppId(String appId) {
        this.appId = appId;
    }

    public List<DataUnit> getDataUnits() {
        return dataUnits;
    }

    public void setDataUnits(List<DataUnit> dataUnits) {
        this.dataUnits = dataUnits;
    }
}
