package com.ctrip.infosec.rule.convert.config;

import com.ctrip.infosec.configs.Caches;
import com.ctrip.infosec.configs.ConfigsLoadedCallback;
import com.ctrip.infosec.rule.convert.ConverterLocator;
import org.springframework.jmx.export.annotation.ManagedResource;

/**
 * Created by yxjiang on 2015/6/15.
 */
@ManagedResource
public class ConvertRuleUpdateCallback implements ConfigsLoadedCallback {
    @Override
    public void onConfigsLoaded() {
//        Caches.
//        ConverterLocator.updateInteralConvertConfig();
        InternalConvertConfigHolder.reconfigurate(Caches.riskFactConvertRuleConfigs,
                Caches.internalRiskFactDefinitionConfigs,
                Caches.dataUnitMetadatas);
    }
}
