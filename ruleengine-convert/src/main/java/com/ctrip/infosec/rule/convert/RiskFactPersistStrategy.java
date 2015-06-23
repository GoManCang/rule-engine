package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.configs.event.DataUnitMetadata;
import com.ctrip.infosec.configs.event.InternalRiskFactPersistConfig;
import com.ctrip.infosec.configs.event.RdbmsTableOperationConfig;
import com.ctrip.infosec.configs.event.enums.DataUnitType;
import com.ctrip.infosec.rule.convert.config.RiskFactPersistConfigHolder;
import com.ctrip.infosec.rule.convert.internal.DataUnit;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.ctrip.infosec.rule.convert.persist.DbOperation;
import com.ctrip.infosec.rule.convert.persist.DbOperationChain;
import com.ctrip.infosec.rule.convert.persist.RiskFactPersistManager;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/15.
 */
public class RiskFactPersistStrategy {
    public static RiskFactPersistManager preparePersistance(InternalRiskFact fact) {
        RiskFactPersistManager persistManager = new RiskFactPersistManager();
        InternalRiskFactPersistConfig config = RiskFactPersistConfigHolder.localPersistConfigs.get(fact.getEventPoint());
        persistManager.setOperationChain(buildDbOperationChain(fact, config));
        return persistManager;
    }

    private static DbOperationChain buildDbOperationChain(InternalRiskFact fact, InternalRiskFactPersistConfig config) {
        DbOperationChain firstOne = null;
        DbOperationChain last = null;
        List<RdbmsTableOperationConfig> opConfigs = config.getOps();
        for (RdbmsTableOperationConfig operationConfig : opConfigs) {
            DataUnitMetadata meta = getMetadata(operationConfig.getDataUnitMetaId());
            DbOperationChain chain = buildDbOperationChain(findCorrespondingDataUnit(fact, meta.getName()), operationConfig, meta);
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
        return firstOne;
    }

    private static DbOperationChain buildDbOperationChain(DataUnit dataUnit, RdbmsTableOperationConfig config, DataUnitMetadata meta) {
        if (dataUnit == null) {
            return null;
        }
        DataUnitType type = DataUnitType.getByCode(dataUnit.getDefinition().getType());
        switch (type) {
            case SINGLE:
                return buildDbOperationChain((Map<String, Object>) dataUnit.getData(), config, meta);
            case LIST:
                return buildDbOperationChain((List<Map<String, Object>>) dataUnit.getData(), config, meta);
        }
        return null;
    }

    private static DbOperationChain buildDbOperationChain(List<Map<String, Object>> dataList, RdbmsTableOperationConfig config, DataUnitMetadata meta) {
        DbOperationChain firstOne = null;
        DbOperationChain last = null;
        if (CollectionUtils.isNotEmpty(dataList)) {
            for (Map<String, Object> data : dataList) {
                DbOperationChain chain = buildDbOperationChain(data, config, meta);
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

    private static DbOperationChain buildDbOperationChain(Map<String, Object> data, RdbmsTableOperationConfig config, DataUnitMetadata meta) {
        Map<String, Object> fieldMap = extractFieldData(data, meta);
        return null;
    }

    private static Map<String, Object> extractFieldData(Map<String, Object> data, DataUnitMetadata meta) {

        return null;
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
