package com.ctrip.infosec.rule.convert.persist;

import com.ctrip.infosec.configs.event.DistributionChannel;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.rule.convert.util.DalDataSourceHolder;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

/**
 * Created by yxjiang on 2015/7/13.
 */
public abstract class AbstractRdbmsOperation  implements DbOperation {
    /**
     * 数据分发通道
     */
    protected DistributionChannel channel;
    protected String table;
    /**
     * key: 数据序列  value： 数据来源和 表达式
     */
    protected Map<String, PersistColumnProperties> columnPropertiesMap;
    private Logger logger = LoggerFactory.getLogger(AbstractRdbmsOperation.class);

    private static String CTX = "ctx";
    private static String CONST = "const";

    protected DataSource getDatasource() throws Exception {
        return DalDataSourceHolder.getDataSource(getChannel().getDatabaseURL());
    }

    protected Object valueByPersistSourceType(PersistColumnProperties persistColumnProperties, PersistContext ctx) {
        PersistColumnSourceType sourceType = persistColumnProperties.getPersistColumnSourceType();
        switch (sourceType) {
            case DB_PK:
                return persistColumnProperties.getValue();
            case DATA_UNIT:
                return persistColumnProperties.getValue();
            case CUSTOMIZE:
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
        if (strings.size() <= 1 || strings.size() > 3) {
            return null;
        }
        if (strings.get(0).equalsIgnoreCase(CTX)) {
            return ctx.getVar(strings.get(1));
        } else if (strings.get(0).equalsIgnoreCase(CONST)) {
            String value = strings.get(1);
            if (strings.size() == 3) {
                String type = strings.get(2);
                switch (type.toLowerCase()) {
                    case "int":
                        return Integer.valueOf(value);
                    case "long":
                        return Long.valueOf(value);
                    case "date":
                        if (value.equalsIgnoreCase("now")) {
                            return new Date();
                        } else {
                            return new Date();
                        }
                    case "double":
                        return Double.valueOf(value);
                    default:
                        return null;
                }
            } else {
                return value;
            }
        } else {
            logger.warn("自定义表达式无效返回null, {}", expression);
            return null;
        }
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
    public String getPrefix() {
        return this.getTable();
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "{" +
                "channel=" + getChannel() +
                ", table='" + getTable() + '\'' +
                ", columnPropertiesMap=" + getColumnPropertiesMap() +
                '}';
    }
}
