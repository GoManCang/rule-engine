package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.configs.event.DataUnitColumnType;
import com.ctrip.infosec.configs.event.DatabaseType;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.rule.convert.util.PersistConvertUtils;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.google.common.base.Joiner;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.sql.*;
import java.text.ParseException;
import java.util.*;
import java.util.Date;

/**
 * Created by jizhao on 2015/6/23.
 */
public class RdbmsInsert extends AbstractRdbmsOperation {

    private Long primary_key;

    private Logger logger = LoggerFactory.getLogger(RdbmsInsert.class);


    @Override
    public void execute(PersistContext ctx) throws DbExecuteException {
        if (getColumnPropertiesMap() == null || getColumnPropertiesMap().size() == 0) {
            logger.warn("columnPropertiesMap为空无数据插入");
            return;
        }

        DatabaseType databaseType = getChannel().getDatabaseType();
        if (databaseType.equals(DatabaseType.AllInOne_SqlServer)) {

            DataSource dataSource;
            Connection connection = null;
            try {
                dataSource = getDatasource();
                connection = dataSource.getConnection();
                String spa = createSPA(getTable(), getColumnPropertiesMap(), ctx);
                if (StringUtils.isBlank(spa)) {
                    logger.warn("columnPropertiesMap 中的value为空 未构成spa");
                    return;
                }
                logger.debug("{}spa: {}, parameters: {}", SarsMonitorContext.getLogPrefix(), spa, getColumnPropertiesMap());
                CallableStatement cs = connection.prepareCall(spa);
                int pk_Index = setValues(databaseType, cs, getColumnPropertiesMap());
                cs.execute();
                if (pk_Index != 0) {
                    primary_key = cs.getLong(pk_Index);
                }

            } catch (Exception e) {
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
        if (StringUtils.isNotBlank(join)) {
            return String.format(sqa, join);
        } else {
            return null;
        }
    }

    /**
     * outPUtIndex 主键index；
     *
     * @param databaseType
     * @param cs
     * @param columnPropertiesMap
     * @return
     * @throws java.sql.SQLException
     */
    private int setValues(DatabaseType databaseType, CallableStatement cs, Map<String, PersistColumnProperties> columnPropertiesMap) throws Exception {
        int outputIndex = 0;
        int index = 1;
//        int size = columnPropertiesMap.size();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            PersistColumnProperties value = entry.getValue();
            if (!value.getPersistColumnSourceType().equals(PersistColumnSourceType.DB_PK)) {
                Object o = normalize(value.getValue());
                if (o != null) {
                    setValue(databaseType, cs, index, value, o);
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

    @Override
    public Map<String, Object> getExposedValue() {
        Map map = new HashMap<>();
        for (Map.Entry<String, PersistColumnProperties> entry : getColumnPropertiesMap().entrySet()) {
            if (entry.getValue().getPersistColumnSourceType() != PersistColumnSourceType.DB_PK) {
                map.put(entry.getKey(), normalize(entry.getValue().getValue()));
            } else {
                map.put(entry.getKey(), primary_key);
            }
        }

        return map;
    }


}
