package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.configs.event.DataUnitColumnType;
import com.ctrip.infosec.configs.event.DatabaseType;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.rule.convert.util.PersistConvertUtils;
import com.ctrip.infosec.sars.monitor.SarsMonitorContext;
import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Predicate;
import com.google.common.collect.Collections2;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.CallableStatementCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;

import java.math.BigDecimal;
import java.sql.*;
import java.text.ParseException;
import java.util.*;
import java.util.Date;

/**
 * Created by yxjiang on 2015/7/13.
 */
public class RdbmsUpdate extends AbstractRdbmsOperation {
    private static final Logger logger = LoggerFactory.getLogger(RdbmsUpdate.class);

    @Override
    public void execute(final PersistContext ctx) throws DbExecuteException {
        if (getColumnPropertiesMap() == null || getColumnPropertiesMap().size() == 0) {
            logger.warn("columnPropertiesMap为空无数据插入");
            return;
        }

        try {
            JdbcTemplate template = new JdbcTemplate(getDatasource());

            final DatabaseType databaseType = getChannel().getDatabaseType();
            if (databaseType.equals(DatabaseType.AllInOne_SqlServer)) {
                String spa = createSPA(getTable(), getColumnPropertiesMap(), ctx);
                if (StringUtils.isBlank(spa)) {
                    logger.info("columnPropertiesMap 中的value为空 未构成spa");
                    return;
                }
                logger.info("{}spa: {}, parameters: {}", SarsMonitorContext.getLogPrefix(), spa, getColumnPropertiesMap());
                template.execute(spa, new CallableStatementCallback<Object>() {
                    @Override
                    public Object doInCallableStatement(CallableStatement cs) throws SQLException, DataAccessException {
                        setValues(databaseType, cs, getColumnPropertiesMap());
                        cs.execute();
                        return null;
                    }
                });
            } else {
                final List<SqlParameterHolder> setList = generateSetList(getColumnPropertiesMap(), ctx);
                final List<SqlParameterHolder> whereList = generateWhereList(getColumnPropertiesMap(), ctx);
                if (CollectionUtils.isEmpty(setList)) {
                    logger.info("columnPropertiesMap 中的value为空 未构成update");
                    return;
                }
                if (CollectionUtils.isEmpty(whereList)) {
                    logger.info("columnPropertiesMap 中的主键为空 未构成update");
                    return;
                }
                String sql = createUpdate(getTable(), setList, whereList);
                logger.info("{}update: {}, parameters: {}, where: {}", SarsMonitorContext.getLogPrefix(), sql, setList, whereList);
                template.update(sql, new PreparedStatementSetter() {
                    @Override
                    public void setValues(PreparedStatement ps) throws SQLException {
                        int idx = 1;
                        for (; idx <= setList.size(); idx++) {
                            setValue(ps, idx, setList.get(idx - 1));
                        }
                        for (; idx <= setList.size() + whereList.size(); idx++) {
                            setValue(ps, idx, whereList.get(idx - setList.size() - 1));
                        }
                    }
                });
            }
        } catch (Exception e) {
            throw new DbExecuteException("update操作异常", e);
        }

    }

    private int setValues(DatabaseType databaseType, CallableStatement cs, Map<String, PersistColumnProperties> columnPropertiesMap) throws SQLException {
        int outputIndex = 0;
        int index = 1;
//        int size = columnPropertiesMap.size();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            PersistColumnProperties value = entry.getValue();
            Object o = value.getValue();
            if (o != null) {
                try {
                    setValue(databaseType, cs, index, value, o);
                } catch (ParseException e) {
                    throw new SQLException("set callable statement error. value=" + o, e);
                }
            } else {
                continue;
            }
            index++;
        }
        return outputIndex;
    }

    private String createSPA(String table, Map<String, PersistColumnProperties> columnPropertiesMap, PersistContext ctx) throws SQLException {
//        String sqa = "{call spA_" + table + "_u  (@RuleID = ? , @ProcessType= ? , @CheckValue= ? )}";
        String sqa = "{call spA_" + table + "_u ( %s )}";
        String temp;
        List<String> list = new ArrayList<>();
        for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
            Object o = valueByPersistSourceType(entry.getValue(), ctx);
            if (o != null) {
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

    private void setValue(PreparedStatement ps, int index, SqlParameterHolder sqlParameterHolder) throws SQLException {
        Object o = sqlParameterHolder.getValue();
        if (o != null) {
            if (o instanceof Integer) {
                ps.setInt(index, (Integer) o);
            } else if (o instanceof Long) {
                ps.setLong(index, (Long) o);
            } else if (o instanceof Date) {
                ps.setTimestamp(index, new Timestamp(((Date) o).getTime()));
            } else if (o instanceof String) {
                ps.setString(index, (String) o);
            } else if (o instanceof Double) {
                Double d = (Double) o;
                ps.setBigDecimal(index, new BigDecimal(d));
            } else if (o instanceof Float) {
                Float f = (Float) o;
                ps.setBigDecimal(index, new BigDecimal(f.doubleValue()));
            } else {
                ps.setObject(index, o);
            }
        }
    }

    private String createUpdate(String table, List<SqlParameterHolder> setList, List<SqlParameterHolder> whereList) {
        Collection<String> setClauses = Collections2.transform(setList, new Function<SqlParameterHolder, String>() {
            @Override
            public String apply(SqlParameterHolder input) {
                return input.getColumnName() + " = ?";
            }
        });
        Collection<String> whereClauses = Collections2.transform(whereList, new Function<SqlParameterHolder, String>() {
            @Override
            public String apply(SqlParameterHolder input) {
                return input.getColumnName() + " = ?";
            }
        });
        return "update " + table + " set " + StringUtils.join(setClauses, ", ") + " where " + StringUtils.join(whereClauses, ", ");
    }

    private List<SqlParameterHolder> generateWhereList(Map<String, PersistColumnProperties> columnPropertiesMap, PersistContext ctx) {
        return generateParamsList(columnPropertiesMap, ctx, new Predicate<PersistColumnSourceType>() {
            @Override
            public boolean apply(PersistColumnSourceType input) {
                return input == PersistColumnSourceType.DB_PK;
            }
        });
    }

    private List<SqlParameterHolder> generateSetList(Map<String, PersistColumnProperties> columnPropertiesMap, PersistContext ctx) {
        return generateParamsList(columnPropertiesMap, ctx, new Predicate<PersistColumnSourceType>() {
            @Override
            public boolean apply(PersistColumnSourceType input) {
                return input != PersistColumnSourceType.DB_PK;
            }
        });
    }

    private List<SqlParameterHolder> generateParamsList(Map<String, PersistColumnProperties> columnPropertiesMap, PersistContext ctx, Predicate<PersistColumnSourceType> predicate) {
        if (MapUtils.isNotEmpty(columnPropertiesMap)) {
            List<SqlParameterHolder> list = new ArrayList<>();
            for (Map.Entry<String, PersistColumnProperties> entry : columnPropertiesMap.entrySet()) {
                Object o = valueByPersistSourceType(entry.getValue(), ctx);
                if (o != null && predicate.apply(entry.getValue().getPersistColumnSourceType())) {
                    list.add(new SqlParameterHolder(entry.getKey(), o));
                }
            }
            return list;
        }
        return null;
    }

    @Override
    public Map<String, Object> getExposedValue() {
        Map map = new HashMap<>();
        for (Map.Entry<String, PersistColumnProperties> entry : getColumnPropertiesMap().entrySet()) {
            if (entry.getValue().getPersistColumnSourceType() != PersistColumnSourceType.DB_PK) {
                map.put(entry.getKey(), normalize(entry.getValue().getValue()));
            }
        }

        return map;
    }

    class SqlParameterHolder {
        private String columnName;
        private Object value;

        SqlParameterHolder(String columnName, Object value) {
            this.columnName = columnName;
            this.value = value;
        }

        public String getColumnName() {
            return columnName;
        }

        public Object getValue() {
            return value;
        }
    }
}
