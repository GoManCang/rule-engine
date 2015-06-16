package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.event.FieldMapping;
import com.ctrip.infosec.configs.event.RiskFactConvertRuleConfig;
import com.ctrip.infosec.rule.convert.config.InternalConvertConfigHolder;
import com.ctrip.infosec.rule.convert.config.InternalMappingConfigTree;
import com.ctrip.infosec.rule.convert.internal.DataUnit;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by jizhao on 2015/6/15.
 */
public class RiskFactConvertRule{
    private String eventPoint;
    private List<FieldMapping> mappings;

    public InternalRiskFact apply(RiskFact riskFact){
        /**
         * 设置基础信息
         */
        InternalRiskFact internalRiskFact=new InternalRiskFact();
        internalRiskFact.setEventPoint(riskFact.getEventPoint());
        internalRiskFact.setEventId(riskFact.getEventId());
        internalRiskFact.setAppId(riskFact.getAppId());

        /**
         * eventBoday 转换
         */
        List<DataUnit> dataUnits = new ArrayList<DataUnit>();
        Map<String, Object> eventBody = riskFact.getEventBody();

        Map<String, RiskFactConvertRuleConfig> riskConvertMappings = InternalConvertConfigHolder.getRiskConvertMappings();
        RiskFactConvertRuleConfig riskFactConvertRuleConfigs = riskConvertMappings.get(riskFact.getEventPoint());


        /**
         * 遍历map 将FieldMapping中需要的字段值取出构成InternalRiskFact
         */

        for(Map.Entry<String,Object> entry:eventBody.entrySet()){

        }
        return internalRiskFact;
    }

    

    public String getEventPoint() {
        return eventPoint;
    }

    public void setEventPoint(String eventPoint) {
        this.eventPoint = eventPoint;
    }

    public List<FieldMapping> getMappings() {
        return mappings;
    }

    public void setMappings(List<FieldMapping> mappings) {
        this.mappings = mappings;
    }


}
