package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.configs.event.*;
import com.ctrip.infosec.configs.event.enums.DataUnitType;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.configs.event.enums.PersistOperationType;
import com.ctrip.infosec.rule.convert.config.RiskFactPersistConfigHolder;
import com.ctrip.infosec.rule.convert.internal.DataUnit;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.ctrip.infosec.rule.convert.persist.RiskFactPersistManager;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.meidusa.fastjson.JSON;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Created by yxjiang on 2015/6/24.
 */
public class RiskFactPersistStrategyTest {

    @Test
    public void testPreparePersistence() throws Exception {
        String eventPoint = "test";
        // 配置信息
        InternalRiskFactPersistConfig config = new InternalRiskFactPersistConfig();
        config.setEventPoint(eventPoint);
        config.setOps(getRdbmsTableOperationConfigs());
        RiskFactPersistConfigHolder.localPersistConfigs.put(eventPoint, config);

        DataUnitMetadata meta = new DataUnitMetadata();
        meta.setMetadataNo("complexMeta");
        meta.setName("complexMeta");
        List<DataUnitColumn> dataUnitColumns = Lists.newArrayList();
        DataUnitColumn dataUnitColumn = new DataUnitColumn();
        dataUnitColumn.setName("name");
        dataUnitColumn.setColumnType(DataUnitColumnType.String.getIndex());
        dataUnitColumns.add(dataUnitColumn);
        meta.setColumns(dataUnitColumns);
        RiskFactPersistConfigHolder.localDataUnitMetadatas.put(meta.getName(), meta);
        // 内部对象
        InternalRiskFact fact = new InternalRiskFact();
        fact.setAppId("1");
        fact.setEventId("1");
        fact.setEventPoint(eventPoint);
        List<DataUnit> dataUnits = Lists.newArrayList();
        DataUnit du1 = new DataUnit();
        DataUnitDefinition dud = new DataUnitDefinition();
        dud.setMetadataId(meta.getMetadataNo());
        dud.setType(DataUnitType.SINGLE.getCode());
        dud.setMetadata(meta);
        du1.setDefinition(dud);
        Map<String, Object> data = Maps.newHashMap();
        data.put("name", "user name");
        du1.setData(data);
        dataUnits.add(du1);
        fact.setDataUnits(dataUnits);

        // 获取persistManager
        RiskFactPersistManager persistManager = RiskFactPersistStrategy.preparePersistence(fact);
        persistManager.persist();
        System.out.println(persistManager.getGeneratedReqId());
    }

    private List<RdbmsTableOperationConfig> getRdbmsTableOperationConfigs() {
        List<RdbmsTableOperationConfig> configOps = Lists.newArrayList();
        RdbmsTableOperationConfig op = new RdbmsTableOperationConfig();
        DistributionChannel channel = getChannel("ch1", DatabaseType.AllInOne_SqlServer, "CardRiskDB_INSERT_1");
        op.setChannel(channel);
        op.setChannelId(channel.getChannelNo());
        op.setDataUnitMetaId("complexMeta");
        op.setOpType(PersistOperationType.INSERT.getCode());
        op.setTableName("InfoSecurity_OtherInfo");
        op.setColumns(getRdbmsTableColumnConfigs());
        configOps.add(op);
        return configOps;
    }

    private DistributionChannel getChannel(String channelNo, DatabaseType dbType, String channelUrl) {
        DistributionChannel channel = new DistributionChannel();
        channel.setChannelNo(channelNo);
        channel.setDatabaseType(dbType);
        channel.setChannelDesc(channelNo);
        channel.setDatabaseURL(channelUrl);
        return channel;
    }

    private List<RdbmsTableColumnConfig> getRdbmsTableColumnConfigs() {
        List<RdbmsTableColumnConfig> columnConfigs = Lists.newArrayList();
        columnConfigs.add(getRdbmsTableColumnConfig("ReqID", PersistColumnSourceType.CUSTOMIZE, "ctx:CardRisk_DealInfo.ReqID"));
        columnConfigs.add(getRdbmsTableColumnConfig("OrderInfoExternalURL", PersistColumnSourceType.DATA_UNIT, "name"));
        columnConfigs.add(getRdbmsTableColumnConfig("DataChange_LastTime", PersistColumnSourceType.CUSTOMIZE, "data:now"));
        return columnConfigs;
    }

    private RdbmsTableColumnConfig getRdbmsTableColumnConfig(String name, PersistColumnSourceType srcType, String src) {
        RdbmsTableColumnConfig columnConfig = new RdbmsTableColumnConfig();
        columnConfig.setName(name);
        columnConfig.setSourceType(srcType.getCode());
        columnConfig.setSource(src);
        return columnConfig;
    }
}