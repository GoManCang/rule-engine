package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.event.DataUnitMetadata;
import com.ctrip.infosec.configs.event.InternalRiskFactPersistConfig;
import com.google.common.collect.Maps;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.time.DateUtils;

import java.util.Iterator;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class RiskFactPersistConfigHolder {
    private static final long PURGE_TIMEOUT = DateUtils.MILLIS_PER_DAY;
    private static long lastPurgeTime = System.currentTimeMillis();
    public static final Map<String, InternalRiskFactPersistConfig> localPersistConfigs = Maps.newHashMap();
    public static final Map<String, DataUnitMetadata> localDataUnitMetadatas = Maps.newHashMap();

    public static void reconfigure(Map<String, InternalRiskFactPersistConfig> internalRiskFactPersistConfigs, Map<String, DataUnitMetadata> dataUnitMetadatas) {
        if (MapUtils.isNotEmpty(internalRiskFactPersistConfigs)) {
            for (Map.Entry<String, InternalRiskFactPersistConfig> entry : internalRiskFactPersistConfigs.entrySet()) {
                String key = entry.getKey();
                InternalRiskFactPersistConfig remoteConfig = entry.getValue();
                InternalRiskFactPersistConfig localPersistConfig = localPersistConfigs.get(key);
                if (localPersistConfig == null || localPersistConfig.getUpdatedAt().before(remoteConfig.getUpdatedAt())) {
                    localPersistConfigs.put(key, remoteConfig);
                }
            }
            for (Map.Entry<String, DataUnitMetadata> entry : dataUnitMetadatas.entrySet()) {
                String key = entry.getKey();
                DataUnitMetadata remoteConfig = entry.getValue();
                DataUnitMetadata localMetadataConfig = localDataUnitMetadatas.get(key);
                if (localMetadataConfig == null || localMetadataConfig.getUpdatedAt().before(remoteConfig.getUpdatedAt())) {
                    localDataUnitMetadatas.put(key, remoteConfig);
                }
            }
            // 清空过期配置
            long curTime = System.currentTimeMillis();
            if (curTime > lastPurgeTime + PURGE_TIMEOUT) {
                for (Iterator<Map.Entry<String, InternalRiskFactPersistConfig>> iter = localPersistConfigs.entrySet().iterator(); iter.hasNext();){
                    Map.Entry<String, InternalRiskFactPersistConfig> entry = iter.next();
                    if (internalRiskFactPersistConfigs.get(entry.getKey()) == null && entry.getValue().getUpdatedAt().getTime() < curTime - PURGE_TIMEOUT){
                        iter.remove();
                    }
                }
                for (Iterator<Map.Entry<String, DataUnitMetadata>> iter = localDataUnitMetadatas.entrySet().iterator(); iter.hasNext();){
                    Map.Entry<String, DataUnitMetadata> entry = iter.next();
                    if (dataUnitMetadatas.get(entry.getKey()) == null && entry.getValue().getUpdatedAt().getTime() < curTime - PURGE_TIMEOUT){
                        iter.remove();
                    }
                }
            }
        }
    }
}
