package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.configs.event.DataUnitColumnType;
import com.ctrip.infosec.configs.event.DatabaseType;
import com.ctrip.infosec.configs.event.DistributionChannel;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Created by yxjiang on 2015/7/13.
 */
public class RdbmsUpdateTest {
    private RdbmsUpdate rdbmsUpdate;
    PersistContext ctx;

    @Before
    public void setUp() throws Exception {
        ctx=new PersistContext();

        rdbmsUpdate = new RdbmsUpdate();
        DistributionChannel channel= new DistributionChannel();
        channel.setDatabaseType(DatabaseType.AllInOne_SqlServer);
        channel.setDatabaseURL("CardRiskDB_INSERT_1");
        channel.setSchema("CardRiskDB");

        rdbmsUpdate.setChannel(channel);

    }

    @Test
    public void testExecute() throws Exception {
        /**
         * 随便选了张column少的表。
         */
        rdbmsUpdate.setTable("InfoSecurity_RiskLevelData");

        Map<String , PersistColumnProperties> map =new HashMap<String, PersistColumnProperties>();

        PersistColumnProperties pcp3=new PersistColumnProperties();
        pcp3.setValue(8299509L);
        pcp3.setColumnType(DataUnitColumnType.Long);
        pcp3.setPersistColumnSourceType(PersistColumnSourceType.DB_PK);
        map.put("ReqID", pcp3);

        PersistColumnProperties pcp1 = new PersistColumnProperties();
        pcp1.setValue(32);
        pcp1.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        pcp1.setColumnType(DataUnitColumnType.Int);
        map.put("TransFlag",pcp1);

        PersistColumnProperties pcp2=new PersistColumnProperties();
        pcp2.setValue("T");
        pcp2.setColumnType(DataUnitColumnType.Long);
        pcp2.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        map.put("CMBMsgStatus", pcp2);

        rdbmsUpdate.setColumnPropertiesMap(map);

        rdbmsUpdate.execute(ctx);
    }
}