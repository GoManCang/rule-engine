package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.datasource.locator.DataSourceLocator;
import com.ctrip.infosec.configs.event.DatabaseType;
import com.ctrip.infosec.configs.event.DistributionChannel;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by jizhao on 2015/6/23.
 */
public class RdbmsInsert implements DbOperation {

    private static String DATA = "data";
    private static String CTX = "ctx";
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

    private Logger logger = LoggerFactory.getLogger(RdbmsInsert.class);


    @Override
    public void execute(PersistContext ctx) throws DbExecuteException {
        //todo dataSource  传进来如何

        if (columnPropertiesMap == null || columnPropertiesMap.size() == 0) {
            logger.warn("columnPropertiesMap为空无数据插入");
            return;
        }

        DatabaseType databaseType = channel.getDatabaseType();
        if (databaseType.equals(DatabaseType.AllInOne_SqlServer)) {
            DataSource dataSource;
            try {
                dataSource = DataSourceLocator.newInstance().getDataSource(channel.getDatabaseURL());
                Connection connection = dataSource.getConnection();
                CallableStatement cs = connection.prepareCall(createSPA(table, columnPropertiesMap,ctx));

//                cs.setObject("@RuleID",columnPropertiesMap.get("RuleID").getValue());
//                cs.setObject(1,columnPropertiesMap.get("RuleID").getValue());
//                cs.setObject("@RuleID",columnPropertiesMap.get("RuleID").getValue());
//                cs.setObject("@ProcessType",columnPropertiesMap.get("ProcessType").getValue());
//                cs.setObject(2,columnPropertiesMap.get("ProcessType").getValue());
//                cs.setObject("@CheckValue",columnPropertiesMap.get("CheckValue").getValue());
//                cs.setObject(3,columnPropertiesMap.get("CheckValue").getValue());
                int pk_Index = setValues(cs, columnPropertiesMap, ctx);
                cs.execute();
                if(pk_Index!=0) {
                    primary_key = cs.getLong(pk_Index);
                }

            } catch (Exception e) {
                e.printStackTrace();
                throw new DbExecuteException("insert操作异常", e);
            }
        }
    }

    /**
     * @param table
     * @param columnPropertiesMap
     * @return
     */
    private String createSPA(String table, Map<String, PersistColumnProperties> columnPropertiesMap,PersistContext ctx) throws SQLException {
//        String sqa = "{call spA_" + table + "_i  (@RuleID = ? , @ProcessType= ? , @CheckValue= ? )}";
        String sqa = "{call spA_" + table + "_i ( %s )}";
        String temp = "";
        int index = 0;
        int size = columnPropertiesMap.size();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            if (entry.getValue().getPersistColumnSourceType() != PersistColumnSourceType.DB_PK) {
                Object o = valueByPersistSourceType(entry.getValue(), ctx);
                if(o!=null) {
                    if (index + 1 < size) {
                        temp += "@" + entry.getKey() + " = ?, ";
                    } else {
                        temp += "@" + entry.getKey() + " = ?";
                    }
                }
            }
            index++;
        }
        return String.format(sqa, temp);
//        return sqa;
    }

    /**
     * outPUtIndex 主键index；
     *
     * @param cs
     * @param columnPropertiesMap
     * @return
     * @throws SQLException
     */
    public int setValues(CallableStatement cs, Map<String, PersistColumnProperties> columnPropertiesMap, PersistContext ctx) throws SQLException {
        int outputIndex = 0;
        int index = 1;
//        int size = columnPropertiesMap.size();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            PersistColumnProperties value = entry.getValue();
            if (!value.getPersistColumnSourceType().equals(PersistColumnSourceType.DB_PK)) {
                if(value.getValue()!=null) {
                        cs.setObject(index, value.getValue());
                    //todo  后面根据type 类型 使用 setObject(String parameterName, Object x, int targetSqlType) 方法
//                cs.set
//
//                switch (value.getColumnType()){
//                    case Int:
//                        cs.setInt(index, (Integer) o);
//                        break;
//                    case String:
//                        cs.setString(index, (String) o);
//                        break;
//                    case Long:
//                        cs.setLong(index, (Long) o);
//                        cs.setObject();
//                        break;
//                    default:
//                        throw new SQLException("类型不匹配");
//                }
                }
            } else {
                outputIndex = index;
                cs.registerOutParameter(index, Types.BIGINT);
            }
            index++;
        }
        return outputIndex;
    }

    public Object valueByPersistSourceType(PersistColumnProperties persistColumnProperties, PersistContext ctx) {
        PersistColumnSourceType sourceType = persistColumnProperties.getPersistColumnSourceType();
        switch (sourceType) {
            case DB_PK:
                return null;
            case DATA_UNIT:
                return persistColumnProperties.getValue();
            case CUSTOMIZE:
                //todo 自定义
                persistColumnProperties.setValue(getCustomizeValue(persistColumnProperties.getExpression(), ctx));
                return persistColumnProperties.getValue();
            default:
                logger.warn("列来源错误 返回null");
                return null;
        }
    }

    /**
     * todo 写
     *
     * @param expression
     * @param ctx
     * @return
     */
    public Object getCustomizeValue(String expression, PersistContext ctx) {
        if (StringUtils.isBlank(expression) || ctx == null) {
            logger.warn("expression 表达式无效或者ctx 为空");
            return null;
        }

        ArrayList<String> strings = Lists.newArrayList(Splitter.on(':').trimResults().omitEmptyStrings().split(expression));
        if (strings.size() != 2) {
            return null;
        }
        if (strings.get(0).equalsIgnoreCase(DATA)) {
            String data = strings.get(1);
            switch (data) {
                case "now":
                    return new Date();
                default:
                    logger.warn("日期表达式无效 默认返回当前日期");
                    return new Date();
            }
        } else if (strings.get(0).equalsIgnoreCase(CTX)) {
            //return ctx.get(strings.get[1])
            return null;
        } else {
            logger.warn("自定义表达式无效返回null");
            return null;
        }
    }


    @Override
    public Map<String, Object> getExposedValue() {
        Map map = new HashMap<String, Object>();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            if (entry.getValue().getPersistColumnSourceType() != PersistColumnSourceType.DB_PK) {
                map.put(entry.getKey(), entry.getValue().getValue());
            } else {
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
