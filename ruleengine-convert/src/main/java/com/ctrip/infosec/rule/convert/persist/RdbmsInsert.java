package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.datasource.locator.DataSourceLocator;
import com.ctrip.infosec.configs.event.DatabaseType;
import com.ctrip.infosec.configs.event.DistributionChannel;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;

import javax.sql.DataSource;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Types;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by jizhao on 2015/6/23.
 */
public class RdbmsInsert implements DbOperation {

    /**
     * 数据分发通道
     */
    private DistributionChannel channel;

    private String table;

    /**
     * key: 数据序列  value： 数据来源和 表达式
     */
    private Map<String, PersistColumnProperties> columnPropertiesMap;

    private Long primary_key;


    @Override
    public void execute(PersistContext ctx) throws DbExecuteException {
        //todo dataSource  传进来如何
        DatabaseType databaseType = channel.getDatabaseType();
        if (databaseType.equals(DatabaseType.AllInOne_SqlServer)) {
            DataSource dataSource;
            try {
                dataSource = DataSourceLocator.newInstance().getDataSource(channel.getDatabaseURL());
                Connection connection = dataSource.getConnection();
                CallableStatement cs = connection.prepareCall(createSPA(table, columnPropertiesMap));
                int outIndex = setValues(cs, columnPropertiesMap,ctx);
                cs.execute();
                if(outIndex!=-1) {
                    primary_key = cs.getLong(outIndex);
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new DbExecuteException("获取dataSource异常", e);
            }
        }
    }

    /**
     * @param table
     * @param columnPropertiesMap
     * @return
     */
    private String createSPA(String table, Map<String, PersistColumnProperties> columnPropertiesMap) {
        String sqa = "{call spA_" + table + "_i ( %s )}";
        String temp = "";
        int index = 0;
        int size = columnPropertiesMap.size();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            if (index + 1 < size) {
                temp += "?,";
            } else {
                temp += "?";
            }
            index++;
        }
        return String.format(sqa, temp);
    }

    /**
     * outPUtIndex 主键index；
     *
     * @param cs
     * @param columnPropertiesMap
     * @return
     * @throws SQLException
     */
    private int setValues(CallableStatement cs, Map<String, PersistColumnProperties> columnPropertiesMap,PersistContext ctx) throws SQLException {
        int outputIndex = -1;
        int index = 0;
//        int size = columnPropertiesMap.size();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            PersistColumnProperties value = entry.getValue();
            Object o = valueByPersistSourceType(entry.getValue(),ctx);
            if (!value.getColumnType().equals(PersistColumnSourceType.DB_PK)) {
                cs.setObject(index, o);
            } else {
                outputIndex = index;
                cs.registerOutParameter(index, Types.BIGINT);
            }
            index++;
        }
        return outputIndex;
    }

    private Object valueByPersistSourceType(PersistColumnProperties persistColumnProperties,PersistContext ctx) {
        PersistColumnSourceType sourceType = persistColumnProperties.getPersistColumnSourceType();
        switch (sourceType) {
            case DB_PK:
                return null;
            case DATA_UNIT:
                //todo  set
                return persistColumnProperties.getValue();
            case CUSTOMIZE:
                //todo 自定义
                persistColumnProperties.setValue(getCustomizeValue(persistColumnProperties.getExpression(), ctx));
                return persistColumnProperties.getValue();

            default:
                return null;
        }
    }

    /**
     * todo 写
     * @param expression
     * @param ctx
     * @return
     */
    private Object getCustomizeValue(String expression, PersistContext ctx) {
        return null;
    }


    @Override
    public Map<String, Object> getExposedValue() {
        Map map = new HashMap<String, Object>();
        for (Map.Entry<String, PersistColumnProperties> entry: columnPropertiesMap.entrySet()){
            if(entry.getValue().getPersistColumnSourceType()!= PersistColumnSourceType.DB_PK){
                map.put(entry.getKey(),entry.getValue().getValue());
            }
            else{
                map.put(entry.getKey(), primary_key);
            }
        }

        return map;
    }


    public DistributionChannel getChannel() {
        return channel;
    }

    public void setChannel(DistributionChannel channel) {
        this.channel = channel;
    }

    public String getTable() {
        return table;
    }

    public void setTable(String table) {
        this.table = table;
    }

    public Map<String, PersistColumnProperties> getColumnPropertiesMap() {
        return columnPropertiesMap;
    }

    public void setColumnPropertiesMap(Map<String, PersistColumnProperties> columnPropertiesMap) {
        this.columnPropertiesMap = columnPropertiesMap;
    }

    @Override
    public String toString() {
        return "RdbmsInsert{" +
                "channel=" + channel +
                ", table='" + table + '\'' +
                ", columnPropertiesMap=" + columnPropertiesMap +
                '}';
    }
}
