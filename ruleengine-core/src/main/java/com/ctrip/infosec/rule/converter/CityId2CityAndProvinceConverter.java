package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.rule.resource.DataProxy;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Created by lpxie on 15-4-23.
 */
@Service("cityId2CityAndProvinceConverter")
public class CityId2CityAndProvinceConverter implements Converter {

    private static final Logger logger = LoggerFactory.getLogger(CityId2CityAndProvinceConverter.class);

    static final String serviceName = "ConvertService";
    static final String operationName = "getCityNameByCityId";

    @Override
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper) throws Exception {
        PreActionParam[] fields = preAction.getFields();
        String cityFieldName = (String) fieldMapping.get(fields[0].getParamName());
        String cityFieldValue = BeanUtils.getNestedProperty(fact.eventBody, cityFieldName);

        // prefix default value
        if (Strings.isNullOrEmpty(resultWrapper)) {
            resultWrapper = cityFieldName + "_CityArea";
        }
        // 执行过了就跳过
        if (fact.eventBody.containsKey(resultWrapper)) {
            return;
        }

        if (StringUtils.isNotBlank(cityFieldValue)) {
            Map params = ImmutableMap.of("cityId", cityFieldValue);
            Map result = DataProxy.queryForMap(serviceName, operationName, params);
            if (result != null && !result.isEmpty()) {
                fact.eventBody.put(resultWrapper, result);
            } else {
                if (TraceLogger.hasNestedTrans()) {
                    TraceLogger.traceNestedLog("预处理结果为空. cityId=" + cityFieldValue);
                } else {
                    TraceLogger.traceLog("预处理结果为空. cityId=" + cityFieldValue);
                }
            }
        }
    }
}
