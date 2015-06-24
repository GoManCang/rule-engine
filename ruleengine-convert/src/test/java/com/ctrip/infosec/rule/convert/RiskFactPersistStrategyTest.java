package com.ctrip.infosec.rule.convert;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.ConfigsDeamon;
import com.ctrip.infosec.configs.Part;
import com.ctrip.infosec.configs.event.*;
import com.ctrip.infosec.configs.event.enums.DataUnitType;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.configs.event.enums.PersistOperationType;
import com.ctrip.infosec.configs.utils.Utils;
import com.ctrip.infosec.rule.convert.config.ConvertRuleUpdateCallback;
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
    public void testConvertAndPersist() throws Exception {
        String data = "{\n" +
                "  \"eventPoint\" : \"CP0027004\",\n" +
                "  \"eventBody\" : {\n" +
                "    \"amount\" : \"12631\",\n" +
                "    \"bizCategory\" : \"DIY\",\n" +
                "    \"bizType\" : \"90\",\n" +
                "    \"bookingDate\" : \"2015-06-23 20:32:58\",\n" +
                "    \"currentAmount\" : \"10631\",\n" +
                "    \"finalResultGroupByScene\" : { },\n" +
                "    \"isHide\" : \"false\",\n" +
                "    \"itemInfos\" : [ {\n" +
                "      \"DestCityId\" : \"623\",\n" +
                "      \"DestCityName\" : \"清迈\",\n" +
                "      \"EndDate\" : \"2015-08-12 00:00:00\",\n" +
                "      \"ProductName\" : \"清迈+普吉岛8日7晚自由行·清迈进普吉出 清迈3晚+普吉4晚\",\n" +
                "      \"Remark\" : \"1365008322 最多2人，烦请改订，谢谢//已下1365042339，烦请预订，烦请取消1365008322，差价70元，待确认后补款\",\n" +
                "      \"StartCityId\" : \"2\",\n" +
                "      \"StartCityName\" : \"上海\",\n" +
                "      \"StartDate\" : \"2015-08-05 00:00:00\"\n" +
                "    } ],\n" +
                "    \"merchantOrderType\" : \"机酒\",\n" +
                "    \"message_CreateTime\" : \"2015-6-24 16:44:39\",\n" +
                "    \"operateTime\" : \"2015-06-24 16:44:38\",\n" +
                "    \"orderDescription\" : \"已付款\",\n" +
                "    \"orderId\" : \"1368705150\",\n" +
                "    \"orderStatus\" : \"DIY_PAYED\",\n" +
                "    \"orderType\" : \"机酒\",\n" +
                "    \"orderVersion\" : \"1:1\",\n" +
                "    \"passengers\" : [ {\n" +
                "      \"AgeType\" : \"3\",\n" +
                "      \"BirthDate\" : \"1976-10-13 0:00:00\",\n" +
                "      \"CardNo\" : \"G36616883\",\n" +
                "      \"CardType\" : \"2\",\n" +
                "      \"EName\" : \"ZHANG/JUNCHEN\",\n" +
                "      \"Gender\" : \"1\",\n" +
                "      \"Mobile\" : \"18918182882\",\n" +
                "      \"Nationality\" : \"CN\"\n" +
                "    }, {\n" +
                "      \"AgeType\" : \"3\",\n" +
                "      \"BirthDate\" : \"1978-10-27 0:00:00\",\n" +
                "      \"CardNo\" : \"E17489998\",\n" +
                "      \"CardType\" : \"2\",\n" +
                "      \"EName\" : \"WU/WENQING\",\n" +
                "      \"Gender\" : \"0\",\n" +
                "      \"Mobile\" : \"13331952188\",\n" +
                "      \"Nationality\" : \"CN\"\n" +
                "    }, {\n" +
                "      \"AgeType\" : \"2\",\n" +
                "      \"BirthDate\" : \"2004-7-10 0:00:00\",\n" +
                "      \"CardNo\" : \"E17489997\",\n" +
                "      \"CardType\" : \"2\",\n" +
                "      \"EName\" : \"ZHANG/YUQING\",\n" +
                "      \"Gender\" : \"0\",\n" +
                "      \"Mobile\" : \"18916167872\",\n" +
                "      \"Nationality\" : \"CN\"\n" +
                "    } ],\n" +
                "    \"postActions\" : { },\n" +
                "    \"priceAdjust\" : \"0.0000\",\n" +
                "    \"processOper\" : \"n09728\",\n" +
                "    \"sourceFromCode\" : \"Web\",\n" +
                "    \"uid\" : \"w10wq27\",\n" +
                "    \"usedTime\" : \"2015-08-05 00:00:00\"\n" +
                "  }\n" +
                "}";
        RiskFact fact = Utils.JSON.parseObject(data, RiskFact.class);
        ConfigsDeamon daemon = new ConfigsDeamon();

        daemon.setUrl("http://localhost:8080/configsws/rest/loadconfig");
        daemon.setPart(Part.FactPersistConfig);
        daemon.setCallback(new ConvertRuleUpdateCallback());
        daemon.start();

//        Thread.sleep(10000);
        InternalRiskFact internalRiskFact = new RiskFactConvertRuleService().apply(fact);
        System.out.println(Utils.JSON.toPrettyJSONString(internalRiskFact.getDataUnits()));
        RiskFactPersistManager persistManager = RiskFactPersistStrategy.preparePersistence(internalRiskFact);

        persistManager.persist();
        internalRiskFact.setReqId(persistManager.getGeneratedReqId());

        System.out.println(internalRiskFact.getReqId());
    }

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