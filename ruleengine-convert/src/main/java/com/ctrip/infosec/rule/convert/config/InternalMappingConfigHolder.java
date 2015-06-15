package com.ctrip.infosec.rule.convert.config;

import java.util.List;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class InternalMappingConfigHolder {
    private String eventPoint;
    private List<InternalMappingConfigTree> mappingConfigRoots;
    /**
     * 更新时间
     */
    private long updateAt;

    public String getEventPoint() {
        return eventPoint;
    }

    public void setEventPoint(String eventPoint) {
        this.eventPoint = eventPoint;
    }

    public List<InternalMappingConfigTree> getMappingConfigRoots() {
        return mappingConfigRoots;
    }

    public void setMappingConfigRoots(List<InternalMappingConfigTree> mappingConfigRoots) {
        this.mappingConfigRoots = mappingConfigRoots;
    }

    public long getUpdateAt() {
        return updateAt;
    }

    public void setUpdateAt(long updateAt) {
        this.updateAt = updateAt;
    }
}
