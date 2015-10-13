package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.event.DataUnitMetadata;
import com.ctrip.infosec.configs.event.InternalRiskFactPersistConfig;
import com.google.common.collect.Maps;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.collections.Predicate;
import org.apache.commons.lang3.time.DateUtils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/19.
 */
public class RiskFactPersistConfigHolder {
    private static final long PURGE_TIMEOUT = DateUtils.MILLIS_PER_MINUTE;
    private static long lastPurgeTime = System.currentTimeMillis();
    public static final Map<String, List<InternalRiskFactPersistConfig>> localPersistConfigs = Maps.newHashMap();
    public static final Map<String, DataUnitMetadata> localDataUnitMetadatas = Maps.newHashMap();

    public static void reconfigure(Map<String, List<InternalRiskFactPersistConfig>> internalRiskFactPersistConfigs, Map<String, DataUnitMetadata> dataUnitMetadatas) {
        if (MapUtils.isNotEmpty(internalRiskFactPersistConfigs)) {
            for (Map.Entry<String, List<InternalRiskFactPersistConfig>> entry : internalRiskFactPersistConfigs.entrySet()) {
                String key = entry.getKey();
                List<InternalRiskFactPersistConfig> remoteConfigs = entry.getValue();
                if (CollectionUtils.isNotEmpty(remoteConfigs)) {
                    for (final InternalRiskFactPersistConfig remoteConfig : remoteConfigs) {
                        List<InternalRiskFactPersistConfig> localPersistConfigList = localPersistConfigs.get(key);
                        if (localPersistConfigList == null) {
                            localPersistConfigList = new ArrayList<>();
                            localPersistConfigs.put(key, localPersistConfigList);
                        }
                        InternalRiskFactPersistConfig matchedLocal = (InternalRiskFactPersistConfig) CollectionUtils.find(localPersistConfigList, new Predicate() {
                            @Override
                            public boolean evaluate(Object object) {
                                InternalRiskFactPersistConfig input = (InternalRiskFactPersistConfig) object;
                                return remoteConfig.getId().equals(input.getId());
                            }
                        });
                        if (matchedLocal == null) {
                            localPersistConfigList.add(remoteConfig);
                        } else if (matchedLocal.getUpdatedAt().before(remoteConfig.getUpdatedAt())) {
                            localPersistConfigList.remove(matchedLocal);
                            localPersistConfigList.add(remoteConfig);
                        }
                    }
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
                for (Iterator<Map.Entry<String, List<InternalRiskFactPersistConfig>>> iter = localPersistConfigs.entrySet().iterator(); iter.hasNext(); ) {
                    Map.Entry<String, List<InternalRiskFactPersistConfig>> entry = iter.next();
                    List<InternalRiskFactPersistConfig> remoteConfigList = internalRiskFactPersistConfigs.get(entry.getKey());
                    List<InternalRiskFactPersistConfig> localPersistConfigList = entry.getValue();
                    if (remoteConfigList == null) {
                        if (CollectionUtils.isNotEmpty(localPersistConfigList)) {
                            for (Iterator<InternalRiskFactPersistConfig> localConfigIter = localPersistConfigList.iterator(); localConfigIter.hasNext(); ) {
                                final InternalRiskFactPersistConfig localConfig = localConfigIter.next();
                                if (localConfig.getUpdatedAt().getTime() < curTime - PURGE_TIMEOUT) {
                                    localConfigIter.remove();
                                }
                            }
                        }
                        if (CollectionUtils.isEmpty(localPersistConfigList)) {
                            iter.remove();
                        }
                    } else {
                        if (CollectionUtils.isNotEmpty(localPersistConfigList)) {
                            for (Iterator<InternalRiskFactPersistConfig> localConfigIter = localPersistConfigList.iterator(); localConfigIter.hasNext(); ) {
                                final InternalRiskFactPersistConfig localConfig = localConfigIter.next();
                                InternalRiskFactPersistConfig matchedRemote = (InternalRiskFactPersistConfig) CollectionUtils.find(remoteConfigList, new Predicate() {
                                    @Override
                                    public boolean evaluate(Object object) {
                                        InternalRiskFactPersistConfig input = (InternalRiskFactPersistConfig) object;
                                        return localConfig.getId().equals(input.getId());
                                    }
                                });
                                if (matchedRemote == null && localConfig.getUpdatedAt().getTime() < curTime - PURGE_TIMEOUT) {
                                    localConfigIter.remove();
                                }
                            }
                        }
                    }

                }
                for (Iterator<Map.Entry<String, DataUnitMetadata>> iter = localDataUnitMetadatas.entrySet().iterator(); iter.hasNext(); ) {
                    Map.Entry<String, DataUnitMetadata> entry = iter.next();
                    if (dataUnitMetadatas.get(entry.getKey()) == null && entry.getValue().getUpdatedAt().getTime() < curTime - PURGE_TIMEOUT) {
                        iter.remove();
                    }
                }
            }
        }
    }
}
