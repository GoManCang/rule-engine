package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
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

import java.util.ArrayList;
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

    public static boolean supportLocally(String eventPoint) {
        List<InternalRiskFactPersistConfig> configList = RiskFactPersistConfigHolder.localPersistConfigs.get(eventPoint);
        return CollectionUtils.isNotEmpty(configList);
    }

    public static RiskFactPersistManager preparePersistence(RiskFact riskFact, InternalRiskFact fact, Long outerRiskReqId) {
        RiskFactPersistManager persistManager = new RiskFactPersistManager();
        if (fact != null) {
            List<InternalRiskFactPersistConfig> configList = RiskFactPersistConfigHolder.localPersistConfigs.get(fact.getEventPoint());
            persistManager.setOperationChain(buildDbOperationChain(riskFact, fact, configList, outerRiskReqId));
        }
        return persistManager;
    }

    private static DbOperationChain buildDbOperationChain(RiskFact riskFact, InternalRiskFact fact, List<InternalRiskFactPersistConfig> configList, Long outerRiskReqId) {
        if (CollectionUtils.isEmpty(configList)) {
            return null;
        }
        List<RdbmsTableOperationConfig> opConfigs = getMatchedOps(riskFact, configList);
        if (CollectionUtils.isEmpty(opConfigs)) {
            return null;
        }
        DbOperationChain firstOne = genReqIdOperationChain(outerRiskReqId);
        // 业务消息落地
        DbOperationChain last = firstOne;
        if (CollectionUtils.isNotEmpty(opConfigs)) {
            for (RdbmsTableOperationConfig operationConfig : opConfigs) {
                DataUnitMetadata meta = getMetadata(operationConfig.getDataUnitMetaId());
                if (meta == null) {
                    continue;
                }
                DbOperationChain chain = buildDbOperationChain(fact, findCorrespondingDataUnit(fact, meta.getName()), operationConfig, meta, opConfigs);
                if (chain != null) {
                    if (firstOne == null) {
                        firstOne = chain;
                    }
                    if (last != null) {
                        last.addToTail(chain);
                    }
                    last = chain;
                }
            }
        }
        return firstOne;
    }

    private static List<RdbmsTableOperationConfig> getMatchedOps(RiskFact riskFact, List<InternalRiskFactPersistConfig> configList) {
        List<RdbmsTableOperationConfig> result = new ArrayList<>();
        for (InternalRiskFactPersistConfig config : configList) {
            if (Configs.match(config.getConditions(), config.getConditionsLogical(), riskFact.eventBody)) {
                result.addAll(config.getOps());
            }
        }
        return result;
    }

    private static DbOperationChain genReqIdOperationChain(final Long outerRiskReqId) {
        // 没有reqId，新增，否则使用已有的reqId
        if (outerRiskReqId == null) {
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
        } else {
            return new DbOperationChain(new RdbmsEmptyOperation() {
                @Override
                public Map<String, Object> getExposedValue() {
                    Map<String, Object> merged = Maps.newHashMap();
                    merged.putAll(super.getExposedValue());
                    merged.put(PersistContext.getReqIdKey(), outerRiskReqId);
                    return merged;
                }
            });
        }
    }

    private static DbOperationChain buildDbOperationChain(InternalRiskFact fact, DataUnit dataUnit, RdbmsTableOperationConfig config,
                                                          DataUnitMetadata meta, List<RdbmsTableOperationConfig> opConfigs) {
        if (dataUnit == null) {
            return null;
        }
        DataUnitType type = DataUnitType.getByCode(dataUnit.getDefinition().getType());
        switch (type) {
            case SINGLE:
                return buildDbOperationChain(fact, (Map<String, Object>) dataUnit.getData(), config, meta, opConfigs);
            case LIST:
                return buildDbOperationChain(fact, (List<Map<String, Object>>) dataUnit.getData(), config, meta, opConfigs);
        }
        return null;
    }

    private static DbOperationChain buildDbOperationChain(InternalRiskFact fact, List<Map<String, Object>> dataList, RdbmsTableOperationConfig config,
                                                          DataUnitMetadata meta, List<RdbmsTableOperationConfig> opConfigs) {
        DbOperationChain firstOne = null;
        DbOperationChain last = null;
        if (CollectionUtils.isNotEmpty(dataList)) {
            for (Map<String, Object> data : dataList) {
                DbOperationChain chain = buildDbOperationChain(fact, data, config, meta, opConfigs);
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

    private static DbOperationChain buildDbOperationChain(InternalRiskFact fact, Map<String, Object> data, RdbmsTableOperationConfig config,
                                                          DataUnitMetadata meta, List<RdbmsTableOperationConfig> opConfigs) {
        DbOperationChain chain = null;
        if(config != null){
            // 简单类型，对应一个落地操作
            Map<String, Object> simpleFieldMap = extractFieldData(data, meta);
            PersistOperationType operationType = PersistOperationType.getByCode(config.getOpType());
            if (operationType == PersistOperationType.INSERT) {
                RdbmsInsert insert = new RdbmsInsert();
                insert.setChannel(config.getChannel());
                insert.setTable(config.getTableName());
                insert.setColumnPropertiesMap(generateColumnProperties(simpleFieldMap, config, meta));
                chain = new DbOperationChain(insert, config.getConditions(), config.getConditionsLogical(), data);
            }
        }
        if (chain == null) {
            chain = new DbOperationChain(new RdbmsEmptyOperation(), config.getConditions(), config.getConditionsLogical(), data);
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
                            chain.addToChildOperationChain(buildDbOperationChain(fact, map, getPersistConfig(opConfigs, metaColumn.getNestedDataUnitMataNo()),
                                    metaColumn.getNestedDataUnitMeta(), opConfigs));
                            break;
                        case List:
                            List<Map<String, Object>> list = (List<Map<String, Object>>) entry.getValue();
                            chain.addToChildOperationChain(buildDbOperationChain(fact, list, getPersistConfig(opConfigs, metaColumn.getNestedDataUnitMataNo()),
                                    metaColumn.getNestedDataUnitMeta(), opConfigs));
                            break;
                        default:
                            continue;
                    }
                }
            }
        }
        return chain;
    }

    private static RdbmsTableOperationConfig getPersistConfig(List<RdbmsTableOperationConfig> configOps, final String metadataId) {
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
        Map<String, Object> rt = Maps.newHashMap();
        if (MapUtils.isNotEmpty(data)) {
            List<DataUnitColumn> columns = meta.getColumns();
            if (CollectionUtils.isNotEmpty(columns)) {
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
