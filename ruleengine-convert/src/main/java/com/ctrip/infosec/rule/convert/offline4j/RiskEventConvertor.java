package com.ctrip.infosec.rule.convert.offline4j;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Caches;
import com.ctrip.infosec.configs.event.DataUnitDefinition;
import com.ctrip.infosec.configs.event.HeaderMapping;
import com.ctrip.infosec.configs.event.HeaderMappingBizType;
import com.ctrip.infosec.configs.utils.EventBodyUtils;
import com.ctrip.infosec.rule.convert.internal.DataUnit;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

@Service
public class RiskEventConvertor {
	
	private Logger logger = LoggerFactory.getLogger(this.getClass());

	/**
	 * 转换指定业务的risk event对象
	 * @param internalRiskFact
	 * @param riskFact
	 * @param bizType
	 * @return
	 * @throws Exception
	 */
	public Object convert(InternalRiskFact internalRiskFact, RiskFact riskFact, 
			HeaderMappingBizType bizType) throws Exception {
		
		if (null==internalRiskFact || null==riskFact || null==bizType) {
			logger.error("param should not be null");
			throw new Exception("param should not be null");
		}
		
		String eventPoint = riskFact.getEventPoint();
		List<HeaderMapping> headerMappings = getHeaderMappings(bizType, eventPoint);

		if (null == headerMappings || headerMappings.size() == 0) {
			logger.warn("no headerMapping found!");
			throw new Exception("no headerMapping found!");
		}
		
		Class<?> dstClass = Class.forName(headerMappings.get(0).getDstClass());
		Field[] declaredFields = dstClass.getDeclaredFields();
		Object object = dstClass.newInstance();
		
		//设置非eventBody字段的值
		Field tmpField = null;
		if (null != (tmpField = getFieldByName(declaredFields, "eventPoint"))) {
			logger.info("set eventPoint = " + internalRiskFact.getEventPoint());
			tmpField.set(object, internalRiskFact.getEventPoint());
		}
		if (null != (tmpField = getFieldByName(declaredFields, "appId"))) {
			logger.info("set appId = " + internalRiskFact.getAppId());
			tmpField.set(object, internalRiskFact.getAppId());
		}
		if (null != (tmpField = getFieldByName(declaredFields, "eventId"))) {
			logger.info("set eventId = " + internalRiskFact.getEventId());
			tmpField.set(object, internalRiskFact.getEventId());
		}
		if (null != (tmpField = getFieldByName(declaredFields, "reqId"))) {
			logger.info("set reqId = " + internalRiskFact.getReqId());
			tmpField.set(object, internalRiskFact.getReqId());
		}
		
		for (HeaderMapping headerMapping : headerMappings) {
			Field field = getFieldByName(declaredFields, headerMapping.getFieldName());
			if (null == field) {
				logger.warn("field " + headerMapping.getFieldName() + " not defined in class " + headerMappings.get(0).getDstClass());
				continue;
			}
			
			Object tmpValue = getValueByPath(riskFact, headerMapping.getSrcPath());
			logger.info("set " + headerMapping.getFieldName() + " = " + tmpValue);
			field.set(object, tmpValue);
		}
		
		//设置eventBody字段的值
		Map<String, Object> eventBodyMap = Maps.newHashMap();
		List<DataUnit> dataUnits = internalRiskFact.getDataUnits();
		for (DataUnit dataUnit : dataUnits) {
			Object data = dataUnit.getData();
			DataUnitDefinition definition = dataUnit.getDefinition();
			
			logger.info("add eventBodyMap key : " + definition.getMetadata().getName() + ", value : " + data);
			eventBodyMap.put(definition.getMetadata().getName(), data);
		}
		
		//dstClass内部默认必须要有eventBody字段
		Field eventBodyField = getFieldByName(declaredFields, "eventBody");
		if (null == eventBodyField) {
			logger.warn("field eventBody not defined in class " + headerMappings.get(0).getDstClass());
		}
		else {
			logger.info("set eventBody = " + eventBodyMap);
			eventBodyField.set(object, eventBodyMap);
		}
		
		return object;
	}
	
	private List<HeaderMapping> getHeaderMappings(HeaderMappingBizType bizType, String eventPoint) {
		
		List<HeaderMapping> headerMappings = Lists.newLinkedList();
		List<HeaderMapping> headerMappingAllList = Caches.headerMappings;
		
		for (HeaderMapping headerMapping : headerMappingAllList) {
			
			if (bizType.equals(headerMapping.getBiz()) && eventPoint.equals(headerMapping.getEventPoint())) {
				headerMappings.add(headerMapping);
			}
		}
		
		return headerMappings;
	}
	
	private Field getFieldByName(Field[] declaredFields, String name) {
		
		for (Field field : declaredFields) {
			if (field.getName().equals(name)) {
				field.setAccessible(true);
				return field;
			}
		}
		
		return null;
	}
	
	private Object getValueByPath(RiskFact riskFact, String path) {
		
		//不支持list
		return EventBodyUtils.value(riskFact.getEventBody(), path);
	}
	
	private Object getValueByPath(InternalRiskFact internalRiskFact, String path) {
		
		//TODO:待实现
		return null;
	}
}
