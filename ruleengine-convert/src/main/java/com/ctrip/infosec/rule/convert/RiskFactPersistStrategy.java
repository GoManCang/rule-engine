package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.configs.event.*;
import com.ctrip.infosec.configs.event.enums.DataUnitType;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.configs.event.enums.PersistOperationType;
import com.ctrip.infosec.rule.convert.config.RiskFactPersistConfigHolder;
import com.ctrip.infosec.rule.convert.internal.DataUnit;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.ctrip.infosec.rule.convert.persist.*;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.google.common.collect.Maps;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.collections.Predicate;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class RiskFactPersistStrategy {
    private static Logger logger = LoggerFactory.getLogger(RiskFactPersistStrategy.class);

    public static final String allInOne4ReqId = GlobalConfig.getString("reqId.allInOne.name");
    public static final String table4ReqId = GlobalConfig.getString("reqId.table.name");
    public static final String column4ReqId = GlobalConfig.getString("reqId.column.name");

    public static RiskFactPersistManager preparePersistence(InternalRiskFact fact) {
        RiskFactPersistManager persistManager = new RiskFactPersistManager();
        if (fact != null) {
            InternalRiskFactPersistConfig config = RiskFactPersistConfigHolder.localPersistConfigs.get(fact.getEventPoint());
            persistManager.setOperationChain(buildDbOperationChain(fact, config));
        }
        return persistManager;
    }

    private static DbOperationChain buildDbOperationChain(InternalRiskFact fact, InternalRiskFactPersistConfig config) {
        if (config == null) {
            return null;
        }
        DbOperationChain firstOne = genReqIdOperationChain();
        // 业务消息落地
        DbOperationChain last = firstOne;
        List<RdbmsTableOperationConfig> opConfigs = config.getOps();
        for (RdbmsTableOperationConfig operationConfig : opConfigs) {
            DataUnitMetadata meta = getMetadata(operationConfig.getDataUnitMetaId());
            if (meta == null) {
                continue;
            }
            DbOperationChain chain = buildDbOperationChain(fact, findCorrespondingDataUnit(fact, meta.getName()), operationConfig, meta);
            if (chain != null) {
                if (firstOne == null) {
                    firstOne = chain;
                }
                if (last != null) {
                    last.setNextOperationChain(chain);
                }
                last = chain;
            }
        }
        // 规则结果落地
//        String eventPoint = fact.getEventPoint();
//        List<HeaderMapping> headerMappings = getHeaderMappings(HeaderMappingBizType.Offline4J, eventPoint);
//        if (CollectionUtils.isNotEmpty(headerMappings)) {
//            RdbmsInsert insert = genRiskLevelInsert();
//            Map<String, PersistColumnProperties> map = Maps.newHashMap();
//            // ReqId
//            PersistColumnProperties props = new PersistColumnProperties();
//            props.setPersistColumnSourceType(PersistColumnSourceType.CUSTOMIZE);
//            props.setColumnType(DataUnitColumnType.Long);
//            props.setExpression("ctx:" + table4ReqId + "." + column4ReqId);
//            map.put("ReqID", props);
//            // RiskLevel
//            props = new PersistColumnProperties();
//            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
//            props.setColumnType(DataUnitColumnType.Int);
//            props.setValue(riskLevel);
//            map.put("RiskLevel", props);
//            // OriginalRiskLevel
//            props = new PersistColumnProperties();
//            props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
//            props.setColumnType(DataUnitColumnType.Int);
//            props.setValue(riskLevel);
//            map.put("OriginalRiskLevel", props);
//            for (HeaderMapping headerMapping : headerMappings) {
//                String fieldName = headerMapping.getFieldName();
//                // 没有配置功能，暂时硬编码
//                if (StringUtils.equals(fieldName, "orderId")) {
//                    props = new PersistColumnProperties();
//                    props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
//                    props.setColumnType(DataUnitColumnType.Long);
//                    props.setValue(getValueByPath(fact, headerMapping.getSrcPath()));
//                    map.put("OrderID", props);
//                }
//                if (StringUtils.equals(fieldName, "orderType")) {
//                    props = new PersistColumnProperties();
//                    props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
//                    props.setColumnType(DataUnitColumnType.Int);
//                    props.setValue(getValueByPath(fact, headerMapping.getSrcPath()));
//                    map.put("OrderType", props);
//                }
//                if (StringUtils.equals(fieldName, "subOrderType")) {
//                    props = new PersistColumnProperties();
//                    props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
//                    props.setColumnType(DataUnitColumnType.Int);
//                    props.setValue(getValueByPath(fact, headerMapping.getSrcPath()));
//                    map.put("SubOrderType", props);
//                }
//            }
//            insert.setColumnPropertiesMap(map);
//            last.setNextOperationChain(new DbOperationChain(insert));
//        }
        return firstOne;
    }

//    private static List<HeaderMapping> getHeaderMappings(HeaderMappingBizType bizType, String eventPoint) {
//        List<HeaderMapping> headerMappings = Lists.newLinkedList();
//        List<HeaderMapping> headerMappingAllList = Caches.headerMappings;
//
//        for (HeaderMapping headerMapping : headerMappingAllList) {
//
//            if (bizType.equals(headerMapping.getBiz()) && eventPoint.equals(headerMapping.getEventPoint())) {
//                headerMappings.add(headerMapping);
//            }
//        }
//        return headerMappings;
//    }

//    private static Object getValueByPath(InternalRiskFact internalRiskFact, String path) {
//        if (StringUtils.isBlank(path))
//            return null;
//
//        List<String> pathList = Splitter.on(".").omitEmptyStrings().trimResults().limit(2).splitToList(path);
//        List<DataUnit> dataUnits = internalRiskFact.getDataUnits();
//        for (DataUnit dataUnit : dataUnits) {
//            if (dataUnit.getMetadata().getName().equals(pathList.get(0))) {
//                if (pathList.size() == 1) {
//                    return dataUnit.getData();
//                } else if (dataUnit.getData() instanceof Map) {//不支持list
//                    return EventBodyUtils.value((Map) dataUnit.getData(), /*path*/pathList.get(1));
//                }
//            }
//        }
//        return null;
//    }

//    private static RdbmsInsert genRiskLevelInsert() {
//        RdbmsInsert insert = new RdbmsInsert();
//        DistributionChannel ch = new DistributionChannel();
//        ch.setChannelNo(allInOne4ReqId);
//        ch.setDatabaseType(DatabaseType.AllInOne_SqlServer);
//        ch.setChannelDesc(allInOne4ReqId);
//        ch.setDatabaseURL(allInOne4ReqId);
//        insert.setChannel(ch);
//        insert.setTable("InfoSecurity_RiskLevelData");
//        return insert;
//    }

    private static DbOperationChain genReqIdOperationChain() {
        RdbmsInsert insert = new RdbmsInsert();
        DistributionChannel ch = new DistributionChannel();
        ch.setChannelNo(allInOne4ReqId);
        ch.setDatabaseType(DatabaseType.AllInOne_SqlServer);
        ch.setChannelDesc(allInOne4ReqId);
        ch.setDatabaseURL(allInOne4ReqId);
        insert.setChannel(ch);
        insert.setTable(table4ReqId);
        PersistColumnProperties props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DB_PK);
        props.setColumnType(DataUnitColumnType.Long);
        Map<String, PersistColumnProperties> map = Maps.newHashMap();
        map.put(column4ReqId, props);
        insert.setColumnPropertiesMap(map);
        return new DbOperationChain(insert);
    }

    private static DbOperationChain buildDbOperationChain(InternalRiskFact fact, DataUnit dataUnit, RdbmsTableOperationConfig config, DataUnitMetadata meta) {
        if (dataUnit == null) {
            return null;
        }
        DataUnitType type = DataUnitType.getByCode(dataUnit.getDefinition().getType());
        switch (type) {
            case SINGLE:
                return buildDbOperationChain(fact, (Map<String, Object>) dataUnit.getData(), config, meta);
            case LIST:
                return buildDbOperationChain(fact, (List<Map<String, Object>>) dataUnit.getData(), config, meta);
        }
        return null;
    }

    private static DbOperationChain buildDbOperationChain(InternalRiskFact fact, List<Map<String, Object>> dataList,
                                                          RdbmsTableOperationConfig config, DataUnitMetadata meta) {
        DbOperationChain firstOne = null;
        DbOperationChain last = null;
        if (CollectionUtils.isNotEmpty(dataList)) {
            for (Map<String, Object> data : dataList) {
                DbOperationChain chain = buildDbOperationChain(fact, data, config, meta);
                if (chain != null) {
                    if (firstOne == null) {
                        firstOne = chain;
                    }
                    if (last != null) {
                        last.setNextOperationChain(chain);
                    }
                    last = chain;
                }
            }
        }
        return firstOne;
    }

    private static DbOperationChain buildDbOperationChain(InternalRiskFact fact, Map<String, Object> data,
                                                          RdbmsTableOperationConfig config, DataUnitMetadata meta) {
        DbOperationChain chain = null;
        // 简单类型，对应一个落地操作
        Map<String, Object> simpleFieldMap = extractFieldData(data, meta);
        if (MapUtils.isNotEmpty(simpleFieldMap)) {
            PersistOperationType operationType = PersistOperationType.getByCode(config.getOpType());
            if (operationType == PersistOperationType.INSERT) {
                RdbmsInsert insert = new RdbmsInsert();
                insert.setChannel(config.getChannel());
                insert.setTable(config.getTableName());
                insert.setColumnPropertiesMap(generateColumnProperties(simpleFieldMap, config, meta));
                chain = new DbOperationChain(insert);
            }
        }
        if (chain == null) {
            chain = new DbOperationChain(new RdbmsEmptyOperation());
        }
        // 复杂类型（Map或List）
        Map<String, Object> complexFieldMap = extractFieldObject(data, meta);
        if (MapUtils.isNotEmpty(complexFieldMap)) {
            if (MapUtils.isNotEmpty(complexFieldMap)) {
                for (Map.Entry<String, Object> entry : complexFieldMap.entrySet()) {
                    String colName = entry.getKey();
                    DataUnitColumn metaColumn = meta.getColumn(colName);
                    DataUnitColumnType columnType = DataUnitColumnType.getByIndex(metaColumn.getColumnType());
                    switch (columnType) {
                        case Object:
                            Map<String, Object> map = (Map<String, Object>) entry.getValue();
                            chain.addToChildOperationChain(buildDbOperationChain(fact, map, getPersistConfig(fact, metaColumn.getNestedDataUnitMataNo()),
                                    metaColumn.getNestedDataUnitMeta()));
                            break;
                        case List:
                            List<Map<String, Object>> list = (List<Map<String, Object>>) entry.getValue();
                            chain.addToChildOperationChain(buildDbOperationChain(fact, list, getPersistConfig(fact, metaColumn.getNestedDataUnitMataNo()),
                                    metaColumn.getNestedDataUnitMeta()));
                            break;
                        default:
                            continue;
                    }
                }
            }
        }
        return chain;
    }

    private static RdbmsTableOperationConfig getPersistConfig(InternalRiskFact fact, final String metadataId) {
        InternalRiskFactPersistConfig config = RiskFactPersistConfigHolder.localPersistConfigs.get(fact.getEventPoint());
        List<RdbmsTableOperationConfig> configOps = config.getOps();
        return (RdbmsTableOperationConfig) CollectionUtils.find(configOps, new Predicate() {
            @Override
            public boolean evaluate(Object obj) {
                RdbmsTableOperationConfig conf = (RdbmsTableOperationConfig) obj;
                return StringUtils.equals(conf.getDataUnitMetaId(), metadataId);
            }
        });
    }

    private static Map<String, PersistColumnProperties> generateColumnProperties(Map<String, Object> simpleFieldMap, RdbmsTableOperationConfig config, DataUnitMetadata meta) {
        List<RdbmsTableColumnConfig> columnConfigs = config.getColumns();
        Map<String, PersistColumnProperties> rt = Maps.newHashMap();
        for (RdbmsTableColumnConfig columnConfig : columnConfigs) {
            PersistColumnSourceType sourceType = PersistColumnSourceType.getByCode(columnConfig.getSourceType());
            PersistColumnProperties props = new PersistColumnProperties();
            props.setExpression(columnConfig.getSource());
            props.setPersistColumnSourceType(sourceType);
            if (sourceType == PersistColumnSourceType.DATA_UNIT) {
                String metaColumnName = columnConfig.getSource();
                DataUnitColumn metaColumn = meta.getColumn(metaColumnName);
                if (metaColumn != null) {
                    props.setValue(simpleFieldMap.get(metaColumnName));
                    props.setColumnType(DataUnitColumnType.getByIndex(metaColumn.getColumnType()));
                } else {
                    logger.warn("{}failed to match column from metadata from [{}.{}]", SarsMonitorContext.getLogPrefix(), meta.getName(), metaColumnName);
                }
            }
            rt.put(columnConfig.getName(), props);
        }
        return rt;
    }

    /**
     * 获取data中类型是简单类型的数据
     *
     * @param data
     * @param meta
     * @return
     */
    private static Map<String, Object> extractFieldData(Map<String, Object> data, DataUnitMetadata meta) {
        Map<String, Object> rt = null;
        if (MapUtils.isNotEmpty(data)) {
            List<DataUnitColumn> columns = meta.getColumns();
            if (CollectionUtils.isNotEmpty(columns)) {
                rt = Maps.newHashMap();
                for (DataUnitColumn column : columns) {
                    String name = column.getName();
                    DataUnitColumnType colType = DataUnitColumnType.getByIndex(column.getColumnType());
                    if (colType != DataUnitColumnType.List && colType != DataUnitColumnType.Object) {
                        Object val = data.get(name);
                        if (val != null) {
                            rt.put(name, val);
                        }
                    }
                }
            }
        }
        return rt;
    }

    /**
     * 获取data中类型是LIST或OBJECT的数据
     *
     * @param data
     * @param meta
     * @return
     */
    private static Map<String, Object> extractFieldObject(Map<String, Object> data, DataUnitMetadata meta) {
        Map<String, Object> rt = null;
        if (MapUtils.isNotEmpty(data)) {
            List<DataUnitColumn> columns = meta.getColumns();
            if (CollectionUtils.isNotEmpty(columns)) {
                rt = Maps.newHashMap();
                for (DataUnitColumn column : columns) {
                    String name = column.getName();
                    DataUnitColumnType colType = DataUnitColumnType.getByIndex(column.getColumnType());
                    if (colType == DataUnitColumnType.List || colType == DataUnitColumnType.Object) {
                        Object val = data.get(name);
                        if (val != null) {
                            rt.put(name, val);
                        }
                    }
                }
                if (rt.size() == 0) {
                    rt = null;
                }
            }
        }
        return rt;
    }

    /**
     * 获取InternalRiskFact中metadata name对应的数据单元
     *
     * @param fact
     * @param metaName
     * @return
     */
    private static DataUnit findCorrespondingDataUnit(InternalRiskFact fact, String metaName) {
        if (CollectionUtils.isNotEmpty(fact.getDataUnits())) {
            for (DataUnit dataUnit : fact.getDataUnits()) {
                if (StringUtils.equals(dataUnit.getMetadata().getName(), metaName)) {
                    return dataUnit;
                }
            }
        }
        return null;
    }

    private static DataUnitMetadata getMetadata(String dataUnitMetaId) {
        return RiskFactPersistConfigHolder.localDataUnitMetadatas.get(dataUnitMetaId);
    }
}
