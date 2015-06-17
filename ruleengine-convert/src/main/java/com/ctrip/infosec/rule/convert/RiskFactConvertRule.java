package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.event.DataUnitDefinition;
import com.ctrip.infosec.configs.event.FieldMapping;
import com.ctrip.infosec.configs.event.InternalRiskFactDefinitionConfig;
import com.ctrip.infosec.configs.event.RiskFactConvertRuleConfig;
import com.ctrip.infosec.rule.convert.config.InternalConvertConfigHolder;
import com.ctrip.infosec.rule.convert.internal.DataUnit;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by jizhao on 2015/6/15.
 */
public class RiskFactConvertRule {
    private String eventPoint;
    private List<FieldMapping> mappings;

    private static int LIST_TYPE = 2;
    private static int OBJECT_TYPE = 1;

    /**
     * key 是target 的 a.b.c 中的 a或b或c
     */
//    private Map<String,DataUnitDefinition> unitDefinitionMap=new HashMap<String, DataUnitDefinition>();
//    private static  List<FieldMapping> fieldMappingList;
    public InternalRiskFact apply(RiskFact riskFact) {
        /**
         * 设置基础信息
         */
        InternalRiskFact internalRiskFact = new InternalRiskFact();
        internalRiskFact.setEventPoint(riskFact.getEventPoint());
        internalRiskFact.setEventId(riskFact.getEventId());
        internalRiskFact.setAppId(riskFact.getAppId());

        /**
         * eventBoday 转换
         */
        List<DataUnit> dataUnits = new ArrayList<DataUnit>();
        Map<String, Object> eventBody = riskFact.getEventBody();

        if (!InternalConvertConfigHolder.getRiskConvertMappings().containsKey(riskFact.getEventPoint())) {
            return null;
        }

        RiskFactConvertRuleConfig riskFactConvertRuleConfigs = InternalConvertConfigHolder.getRiskConvertMappings().get(riskFact.getEventPoint());
        List<FieldMapping> fieldMappingList = riskFactConvertRuleConfigs.getMappings();

        /**
         * key 是 mataUnitMetaData 的name
         */
        Map<String, DataUnitDefinition> unitDefinitionMap = new HashMap<String, DataUnitDefinition>();

        if (InternalConvertConfigHolder.getRiskFactDefinitionConfigMap().containsKey(riskFact.getEventPoint())) {
            return null;
        }
        InternalRiskFactDefinitionConfig internalRiskFactDefinitionConfig = InternalConvertConfigHolder.getRiskFactDefinitionConfigMap().get(riskFact.getEventPoint());
        List<DataUnitDefinition> dataUnitMetas = internalRiskFactDefinitionConfig.getDataUnitMetas();
        for (FieldMapping fieldMapping : fieldMappingList) {
            String targetFieldName = fieldMapping.getTargetFieldName();
            String sourceFieldName = fieldMapping.getSourceFieldName();
            DataUnit dataUnit = createDataUnit(eventBody, sourceFieldName, targetFieldName, unitDefinitionMap, dataUnitMetas);
            dataUnits.add(dataUnit);


        }
        internalRiskFact.setDataUnits(dataUnits);

//        /**
//         * 遍历map 将FieldMapping中需要的字段值取出构成InternalRiskFact
//         */
//        recurseValue(eventBody,"",dataUnits,null);

        return internalRiskFact;
    }

    private DataUnit createDataUnit(Map<String, Object> eventBody,
                                    String sourceFieldName,
                                    String targetFieldName,
                                    Map<String, DataUnitDefinition> unitDefinitionMap,
                                    List<DataUnitDefinition> dataUnitMetas) {

        DataUnit dataUnit = new DataUnit();

//        List<String> paths = Lists.newArrayList(targetFieldName.split("."));
        /**
         * todo 限制支取第一个；
         */
        List<String> paths = Lists.newArrayList(Splitter.on('.').omitEmptyStrings().limit(1).trimResults().split(targetFieldName));
        try {
            for (String path : paths) {
                if (!unitDefinitionMap.containsKey(path)) {
                    boolean isFound = false;
                    for (DataUnitDefinition definition : dataUnitMetas) {
                        if (definition.getMetadata().getName().equals(path)) {
                            unitDefinitionMap.put(path, definition);
                            isFound = true;
                            break;
                        }
                    }
                    if (isFound) {
                        throw new Exception("没有找到第一个path 对应的DataUnitDefinition");
                    }
                }
            }
            DataUnitDefinition dataUnitDefinition = unitDefinitionMap.get(paths.get(0));
//            if(dataUnitDefinition.getType()==LIST_TYPE){
//                dataUnit.setData(new ArrayList<Map<String, Object>>());
//                /**
//                 * 从eventBody中找到sourceFieldName 对应的list值
//                 */
//
//            }
            if (dataUnitDefinition.getType() == OBJECT_TYPE) {
                dataUnit.setData(new HashMap<String, Object>());
                dataUnit.setDefinition(dataUnitDefinition);

                Object value = getValueFromMap(eventBody, sourceFieldName);
                if (value instanceof String) {
                    dataUnit.setDefinition(dataUnitDefinition);
                } else {
                    throw new Exception("取到的value 不是String 对象");
                }
                Map<String, Object> data = (Map<String, Object>) dataUnit.getData();

                data.put(targetFieldName,value);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return dataUnit;
    }

    private Object getValueFromMap(Map<String, Object> mapping, String sourceFieldName) {
        Iterable<String> split = Splitter.on('.').omitEmptyStrings().limit(2).trimResults().split(sourceFieldName);
        ArrayList<String> keys = Lists.newArrayList(split);
        if (keys.size() == 2) {
            String key = keys.get(0);
            Object object = mapping.get(key);
            if (object instanceof Map) {
                return getValueFromMap((Map) object, keys.get(1));
            } else if (object instanceof List) {
                return getValueFromList((List<Object>) object, sourceFieldName);
            } else {
                //todo 这种情况是错误的；
                System.out.println("woring!!!!!");
                return object;
            }
        } else {
            //todo 可能是 map list  string  都有可能
            return mapping.get(keys.get(0));
        }
    }

    private List getValueFromList(List<Object> list, String sourceFieldName) {
        Object tmpValue = null;
        List resultList = new ArrayList();
        for (Object item : list) {
            if (item instanceof Map) {
                tmpValue = getValueFromMap((Map<String, Object>) item, sourceFieldName);
                if (tmpValue != null) {
                    resultList.add(tmpValue);
                }
            } else if (item instanceof List) {
                tmpValue = getValueFromList((List<Object>) item, sourceFieldName);
                if (tmpValue != null) {
                    resultList.add(tmpValue);
                }
            } else {
                //todo 这种情况{"list": [1,2]}
                resultList.add(item);
            }
        }
        return resultList;
    }

//    /**
//     * 遍历obj判断obj是否为map，list 和 String
//     * 判断 a.b.c 的路径是否在sourceFieldName中
//     *
//     * @param obj
//     * @param sourcePath
//     * @param dataUnits
//     */
//    private void recurseValue(Object obj, String sourcePath,List<DataUnit> dataUnits,DataUnit dataUnit){
//        if(obj instanceof Map) {
//            Map<String,Object> map=(Map)obj;
//            for(Map.Entry<String,Object> entry: map.entrySet()){
//                sourcePath=StringUtils.isNotBlank(sourcePath)?sourcePath.concat("."+entry.getKey()):entry.getKey();
//                recurseValue(entry.getValue(),sourcePath, dataUnits,dataUnit==null?null:dataUnit);
//            }
//        }
//        else if(obj instanceof List){
//            List<Object> list = (List<Object>) obj;
//            DataUnit unit=new DataUnit();
//            dataUnit.setData(new ArrayList<Map<String,Object>>());
//            dataUnits.add(unit);
//            for(Object entry: list){
//                recurseValue(entry,sourcePath,dataUnits,unit);
//            }
//        }else {
//            /**
//             * obj 是String 类型
//             * 递归结束点
//             */
//            FieldMapping fieldMapping = sourcePathMatched(sourcePath);
//            if(fieldMapping!=null) {
//                String value = (String) obj;
//                String targetFieldName = fieldMapping.getTargetFieldName();
//                createDataUnitDefinition(targetFieldName,dataUnits,dataUnit==null?null:dataUnit);
//            }
//        }
//    }

//    /**
//     * 如果sourcePath 满足fieldMapping 返回此mapping
//     * @param sourcePath
//     * @return
//     */
//    private FieldMapping sourcePathMatched(String sourcePath){
//        for (FieldMapping fieldMapping:fieldMappingList){
//            String sourceFieldName = fieldMapping.getSourceFieldName();
//            if(sourceFieldName.equals(sourcePath)){
//                return fieldMapping;
//            }
//        }
//        return null;
//    }

    //    /**
//     * @param targetfieldName
//     * @param dataUnits
//     */
//    private void createDataUnitDefinition(String targetfieldName, List<DataUnit> dataUnits, DataUnit dataUnit){
//        if(dataUnit==null){
//            dataUnit=new DataUnit();
//        }
//        int listType=2;
//        int objType=1;
//        InternalRiskFactDefinitionConfig definitionConfig = InternalConvertConfigHolder.getRiskFactDefinitionConfigMap().get(eventPoint);
//        List<DataUnitDefinition> dataUnitMetas = definitionConfig.getDataUnitMetas();
//
//
//        List<String> paths= Lists.newArrayList(targetfieldName.split("."));
//        for(final String path:paths){
//            DataUnitDefinition dataUnitDefinition;
//            if(!unitDefinitionMap.containsKey(path)){
//                Collection<DataUnitDefinition> filter = Collections2.filter(dataUnitMetas, new Predicate<DataUnitDefinition>() {
//                    @Override
//                    public boolean apply(DataUnitDefinition input) {
//                        return input.getMetadata().getName().equals(path);
//                    }
//                });
//                if(filter.isEmpty()&& filter.size()!=1){
//                    return;
//                }
//                else{
//                    dataUnitDefinition=Lists.newArrayList(filter).get(0);
//
//                }
//            }else {
//                dataUnitDefinition = unitDefinitionMap.get(path);
//            }
//            /**
//             * 列表对象
//             */
//            if(dataUnitDefinition.getType()==listType){
//            }
//            /**
//             * 单一对象
//             */
//            if(dataUnitDefinition.getType()==objType){
//                DataUnitMetadata metadata = dataUnitDefinition.getMetadata();
//                metadata
//            }
//
//        }
//
//
//    }
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
