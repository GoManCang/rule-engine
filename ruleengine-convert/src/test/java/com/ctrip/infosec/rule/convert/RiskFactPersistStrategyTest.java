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
import com.ctrip.infosec.rule.convert.offline4j.RiskEventConvertor;
import com.ctrip.infosec.rule.convert.persist.*;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import org.junit.Test;

import java.util.List;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/24.
 */
public class RiskFactPersistStrategyTest {

    @Test
    public void testConvertAndPersist() throws Exception {
        String data = "{\n" +
                "  \"eventPoint\": \"CP0041001\",\n" +
                "  \"eventId\": \"76086930-029a-11e5-967d-5f475aeafb8c\",\n" +
                "  \"appId\": \"670203\",\n" +
                "  \"eventBody\": {\n" +
                "    \"aCity\": 5,\n" +
                "    \"accountBook\": \"\",\n" +
                "    \"bookingName\": \"\",\n" +
                "    \"businessItem\": \"\",\n" +
                "    \"checkType\": 1,\n" +
                "    \"contactEMail\": \"lxyy1118@163.com\",\n" +
                "    \"contactName\": \"ContactName\",\n" +
                "    \"contactTel\": \"0519-8117755\",\n" +
                "    \"dCity\": 6,\n" +
                "    \"departureDate\": \"2014-08-15 10:26:15.302\",\n" +
                "    \"isOnline\": \"T\",\n" +
                "    \"latitude\": 0,\n" +
                "    \"longitude\": 0,\n" +
                "    \"merchantID\": \"12358\",\n" +
                "    \"mobilePhone\": \"15161121660\",\n" +
                "    \"optionItems\": [\n" +
                "      {\n" +
                "        \"optionID\": 15,\n" +
                "        \"optionName\": \"OptionName1\",\n" +
                "        \"optionQty\": 15\n" +
                "      },\n" +
                "      {\n" +
                "        \"optionID\": 16,\n" +
                "        \"optionName\": \"OptionName2\",\n" +
                "        \"optionQty\": 66\n" +
                "      }\n" +
                "    ],\n" +
                "    \"orderAmount\": 12,\n" +
                "    \"orderDate\": \"2014-08-15 10:26:15.302\",\n" +
                "    \"orderID\": 4563086,\n" +
                "    \"orderInfoExternalURL\": \"OrderInfoExternalURL\",\n" +
                "    \"orderPrepayType\": \"CCARD\",\n" +
                "    \"orderType\": 29,\n" +
                "    \"paymentInfos\": [\n" +
                "      {\n" +
                "        \"amount\": 0,\n" +
                "        \"cardInfoID\": 0,\n" +
                "        \"creditCardInfo\": {\n" +
                "          \"bankOfCardIssue\": \"\",\n" +
                "          \"billingAddress\": \"\",\n" +
                "          \"cCardLastNoCode\": \"\",\n" +
                "          \"cCardNoCode\": \"\",\n" +
                "          \"cCardPreNoCode\": \"\",\n" +
                "          \"cValidityCode\": \"\",\n" +
                "          \"cardBin\": \"\",\n" +
                "          \"cardHolder\": \"\",\n" +
                "          \"cardInfoID\": 0,\n" +
                "          \"creditCardType\": 0,\n" +
                "          \"infoID\": 0,\n" +
                "          \"isForigenCard\": \"\",\n" +
                "          \"nationality\": \"\",\n" +
                "          \"nationalityofisuue\": \"\",\n" +
                "          \"stateName\": \"\"\n" +
                "        },\n" +
                "        \"prepayType\": \"\",\n" +
                "        \"refNo\": 0\n" +
                "      },\n" +
                "      {\n" +
                "        \"amount\": 0,\n" +
                "        \"cardInfoID\": 0,\n" +
                "        \"creditCardInfo\": {\n" +
                "          \"bankOfCardIssue\": \"\",\n" +
                "          \"billingAddress\": \"\",\n" +
                "          \"cCardLastNoCode\": \"\",\n" +
                "          \"cCardNoCode\": \"\",\n" +
                "          \"cCardPreNoCode\": \"\",\n" +
                "          \"cValidityCode\": \"\",\n" +
                "          \"cardBin\": \"\",\n" +
                "          \"cardHolder\": \"\",\n" +
                "          \"cardInfoID\": 0,\n" +
                "          \"creditCardType\": 0,\n" +
                "          \"infoID\": 0,\n" +
                "          \"isForigenCard\": \"\",\n" +
                "          \"nationality\": \"\",\n" +
                "          \"nationalityofisuue\": \"\",\n" +
                "          \"stateName\": \"\"\n" +
                "        },\n" +
                "        \"prepayType\": \"\",\n" +
                "        \"refNo\": 0\n" +
                "      }\n" +
                "    ],\n" +
                "    \"productName\": \"ProductName\",\n" +
                "    \"referenceNo\": \"ReferenceNo\",\n" +
                "    \"sendTickerAddr\": \"8117755\",\n" +
                "    \"serverfrom\": \"Serverfrom\",\n" +
                "    \"subOrderType\": 0,\n" +
                "    \"uid\": \"test111111\",\n" +
                "    \"userIP\": \"192.168.1.1\",\n" +
                "    \"userInfos\": [\n" +
                "      {\n" +
                "        \"visitorCardNo\": \"VisitorCardNo2\",\n" +
                "        \"visitorContactInfo\": \"VisitorContactInfo1\",\n" +
                "        \"visitorIDCardType\": 32,\n" +
                "        \"visitorName\": \"VisitorName1\",\n" +
                "        \"visitorNationality\": \"CN\"\n" +
                "      },\n" +
                "      {\n" +
                "        \"visitorCardNo\": \"VisitorCardNo2\",\n" +
                "        \"visitorContactInfo\": \"VisitorContactInfo3\",\n" +
                "        \"visitorIDCardType\": 34,\n" +
                "        \"visitorName\": \"VisitorName2\",\n" +
                "        \"visitorNationality\": \"US\"\n" +
                "      }\n" +
                "    ]\n" +
                "  },\n" +
                "  \"ext\": {\n" +
                "    \"CHANNEL\": \"REST\",\n" +
                "    \"descTimestamp\": 2638350186685\n" +
                "  },\n" +
                "  \"requestTime\": \"2015-05-25 12:56:53.342\",\n" +
                "  \"requestReceive\": \"2015-05-25 12:56:53.315\"\n" +
                "}";
        System.out.println(data);
        RiskFact fact = Utils.JSON.parseObject(data, RiskFact.class);
        ConfigsDeamon daemon = new ConfigsDeamon();

        daemon.setUrl("http://10.2.10.76:8080/configsws/rest/loadconfig");
        daemon.setPart(Part.RuleEngine);
        daemon.setCallback(new ConvertRuleUpdateCallback());
        daemon.start();

//        Thread.sleep(10000);
        InternalRiskFact internalRiskFact = new RiskFactConvertRuleService().apply(fact);
        System.out.println(Utils.JSON.toPrettyJSONString(internalRiskFact.getDataUnits()));
        RiskFactPersistManager persistManager = RiskFactPersistStrategy.preparePersistence(internalRiskFact);

        persistManager.persist(120, "NEW:测试");
        internalRiskFact.setReqId(persistManager.getGeneratedReqId());
        System.out.println(internalRiskFact.getReqId());
        System.out.println(persistManager.getOrderId());
        
        Object riskEvent = new RiskEventConvertor().convert(internalRiskFact, fact, HeaderMappingBizType.Offline4J);
        System.out.println(Utils.JSON.toPrettyJSONString(riskEvent));
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
        persistManager.persist(10, "NEW:测试");
        System.out.println(persistManager.getGeneratedReqId());
    }

    @Test
    public void testInsert() throws DbExecuteException {

        RdbmsInsert insert = new RdbmsInsert();
        DistributionChannel channel = new DistributionChannel();
        channel.setChannelNo("CardRiskDB_INSERT_1");
        channel.setDatabaseType(DatabaseType.AllInOne_SqlServer);
        channel.setChannelDesc("CardRiskDB_INSERT_1");
        channel.setDatabaseURL("CardRiskDB_INSERT_1");
        insert.setChannel(channel);
        insert.setTable("InfoSecurity_CheckResultLog");

        /**
         * [LogID] = 主键
         * [ReqID]
         * [RuleType]
         * [RuleID] = 0
         * [RuleName]
         * [RiskLevel]
         * [RuleRemark]
         * [CreateDate] = now
         * [DataChange_LastTime] = now
         * [IsHighlight] = 1
         */
        Map<String, PersistColumnProperties> map = Maps.newHashMap();
        PersistColumnProperties props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DB_PK);
        props.setColumnType(DataUnitColumnType.Long);
        map.put("LogID", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        props.setColumnType(DataUnitColumnType.Long);
        props.setValue(11L);
        map.put("ReqID", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        props.setColumnType(DataUnitColumnType.String);
        props.setValue("N");
        map.put("RuleType", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        props.setColumnType(DataUnitColumnType.Int);
        props.setValue(0);
        map.put("RuleID", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        props.setColumnType(DataUnitColumnType.String);
        props.setValue("test");
        map.put("RuleName", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        props.setColumnType(DataUnitColumnType.Long);
        props.setValue(102);
        map.put("RiskLevel", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        props.setColumnType(DataUnitColumnType.String);
        props.setValue("test remark");
        map.put("RuleRemark", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.CUSTOMIZE);
        props.setColumnType(DataUnitColumnType.Data);
        props.setExpression("const:now:date");
        map.put("CreateDate", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.CUSTOMIZE);
        props.setColumnType(DataUnitColumnType.Data);
        props.setExpression("const:now:date");
        map.put("DataChange_LastTime", props);

        props = new PersistColumnProperties();
        props.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        props.setColumnType(DataUnitColumnType.Int);
        props.setValue(1);
        map.put("IsHighlight", props);

        insert.setColumnPropertiesMap(map);

        PersistContext ctx = new PersistContext();
        insert.execute(ctx);
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
        columnConfigs.add(getRdbmsTableColumnConfig("ReqID", PersistColumnSourceType.CUSTOMIZE, "ctx:InfoSecurity_DealInfo.ReqID"));
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