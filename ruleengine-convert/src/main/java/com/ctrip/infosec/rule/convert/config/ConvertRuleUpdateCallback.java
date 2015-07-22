package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.Caches;
import com.ctrip.infosec.configs.ConfigsLoadedCallback;
import com.ctrip.infosec.configs.event.DataUnitColumn;
import com.ctrip.infosec.configs.event.DataUnitMetadata;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.jmx.export.annotation.ManagedResource;

import java.util.List;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/15.
 */
@ManagedResource
public class ConvertRuleUpdateCallback implements ConfigsLoadedCallback {
    @Override
    public void onConfigsLoaded() {
//        Caches.
//        ConverterLocator.updateInteralConvertConfig();
        InternalConvertConfigHolder.reconfigure(Caches.riskFactConvertRuleConfigs,
                Caches.internalRiskFactDefinitionConfigs
        );
        RiskFactPersistConfigHolder.reconfigure(Caches.internalRiskFactPersistConfigs, Caches.dataUnitMetadatas);
        initDataUnitMatadata(Caches.dataUnitMetadatas);
    }

    private void initDataUnitMatadata(Map<String, DataUnitMetadata> dataUnitMetadatas) {
        if (MapUtils.isNotEmpty(dataUnitMetadatas)) {
            for (DataUnitMetadata metadata : dataUnitMetadatas.values()) {
                List<DataUnitColumn> columns = metadata.getColumns();
                if (CollectionUtils.isNotEmpty(columns)) {
                    for (DataUnitColumn column : columns) {
                        if(StringUtils.isNotBlank(column.getNestedDataUnitMataNo())){
                            column.setNestedDataUnitMeta(dataUnitMetadatas.get(column.getNestedDataUnitMataNo()));
                        }
                    }
                }
            }
        }
    }
}
