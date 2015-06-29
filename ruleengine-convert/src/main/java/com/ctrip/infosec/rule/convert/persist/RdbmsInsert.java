package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.configs.event.DatabaseType;
import com.ctrip.infosec.configs.event.DistributionChannel;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.rule.convert.util.DalDataSourceHolder;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.math.BigDecimal;
import java.sql.*;
import java.util.*;
import java.util.Date;

/**
 * Created by jizhao on 2015/6/23.
 */
public class RdbmsInsert implements DbOperation {

    private static String DATE = "date";
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
            Connection connection = null;
            try {
                dataSource = DalDataSourceHolder.getDataSource(channel.getDatabaseURL());
                connection = dataSource.getConnection();
                String spa = createSPA(table, columnPropertiesMap, ctx);
                if(StringUtils.isBlank(spa)){
                    logger.info("columnPropertiesMap 中的value为空 未构成spa");
                    return;
                }
                logger.info("{}spa: {}, parameters: {}", SarsMonitorContext.getLogPrefix(), spa, columnPropertiesMap);
                CallableStatement cs = connection.prepareCall(spa);
                int pk_Index = setValues(cs, columnPropertiesMap, ctx);
                cs.execute();
                if (pk_Index != 0) {
                    primary_key = cs.getLong(pk_Index);
                }

            } catch (Exception e) {
                e.printStackTrace();
                throw new DbExecuteException("insert操作异常", e);
            } finally {
                try {
                    if (connection != null) {
                        connection.close();
                    }
                } catch (SQLException e) {
                    throw new DbExecuteException("connect 关闭错误", e);
                }
            }
        }
    }

    /**
     * @param table
     * @param columnPropertiesMap
     * @return
     */
    private String createSPA(String table, Map<String, PersistColumnProperties> columnPropertiesMap, PersistContext ctx) throws SQLException {
//        String sqa = "{call spA_" + table + "_i  (@RuleID = ? , @ProcessType= ? , @CheckValue= ? )}";
        String sqa = "{call spA_" + table + "_i ( %s )}";
        String temp;
        List<String> list = new ArrayList<>();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            Object o = valueByPersistSourceType(entry.getValue(), ctx);
            if (entry.getValue().getPersistColumnSourceType() != PersistColumnSourceType.DB_PK) {
                if (o != null) {
                    temp = "@" + entry.getKey() + " = ?";
                    list.add(temp);
                }
            } else {
                temp = "@" + entry.getKey() + " = ?";
                list.add(temp);
            }
        }
        String join = Joiner.on(',').join(list);
        if(StringUtils.isNotBlank(join)) {
            return String.format(sqa, join);
        }
        else {
            return null;
        }
    }

    /**
     * outPUtIndex 主键index；
     *
     * @param cs
     * @param columnPropertiesMap
     * @return
     * @throws java.sql.SQLException
     */
    private int setValues(CallableStatement cs, Map<String, PersistColumnProperties> columnPropertiesMap, PersistContext ctx) throws SQLException {
        int outputIndex = 0;
        int index = 1;
//        int size = columnPropertiesMap.size();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            PersistColumnProperties value = entry.getValue();
            if (!value.getPersistColumnSourceType().equals(PersistColumnSourceType.DB_PK)) {
                Object o = value.getValue();
                if (o != null) {
                    if (o instanceof Integer) {
                        cs.setInt(index, (Integer) o);
                    } else if (o instanceof Logger) {
                        cs.setLong(index, (Long) o);
                    } else if (o instanceof Date) {
                        cs.setTimestamp(index, new Timestamp(((Date) o).getTime()));
                    } else if (o instanceof String) {
                        cs.setString(index, (String) o);
                    } else if ( o instanceof Double) {
                        Double d = (Double) o;
                        cs.setBigDecimal(index, new BigDecimal(d));
                    } else if(o instanceof  Float){
                        Float f = (Float) o;
                        cs.setBigDecimal(index,new BigDecimal(f.doubleValue()));
                    }
                    else {
                        cs.setObject(index, o);
                    }
                } else {
                    continue;
                }
            } else {
                outputIndex = index;
                cs.registerOutParameter(index, Types.BIGINT);
            }
            index++;
        }
        return outputIndex;
    }

    private Object valueByPersistSourceType(PersistColumnProperties persistColumnProperties, PersistContext ctx) {
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
    private Object getCustomizeValue(String expression, PersistContext ctx) {
        if (StringUtils.isBlank(expression) || ctx == null) {
            logger.warn("expression 表达式无效或者ctx 为空");
            return null;
        }

        ArrayList<String> strings = Lists.newArrayList(Splitter.on(':').trimResults().omitEmptyStrings().split(expression));
        if (strings.size() != 2) {
            return null;
        }
        if (strings.get(0).equalsIgnoreCase(DATE)) {
            String data = strings.get(1);
            switch (data) {
                case "now":
                    return new Date();
                default:
                    logger.warn("日期表达式无效 默认返回当前日期");
                    return new Date();
            }
        } else if (strings.get(0).equalsIgnoreCase(CTX)) {
            return ctx.getVar(strings.get(1));
        } else {
            logger.warn("自定义表达式无效返回null, {}", expression);
            return null;
        }
    }


    @Override
    public Map<String, Object> getExposedValue() {
        Map map = new HashMap<>();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            if (entry.getValue().getPersistColumnSourceType() != PersistColumnSourceType.DB_PK) {
                map.put(entry.getKey(), entry.getValue().getValue());
            } else {
                map.put(entry.getKey(), primary_key);
            }
        }

        return map;
    }

    @Override
    public String getPrefix() {
        return this.table;
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
