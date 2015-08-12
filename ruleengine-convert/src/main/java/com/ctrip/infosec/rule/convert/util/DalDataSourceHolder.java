package com.ctrip.infosec.rule.convert.util;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ctrip.datasource.locator.DataSourceLocator;

import java.util.concurrent.ConcurrentHashMap;

public class DalDataSourceHolder {

    private static Logger logger = LoggerFactory.getLogger(DalDataSourceHolder.class);

    private static ConcurrentHashMap<String, DataSource> dalDataSourceMap = new ConcurrentHashMap<>();

    public static DataSource getDataSource(String allInOneName) throws Exception {

        DataSource dataSource = dalDataSourceMap.get(allInOneName);
        if (dataSource == null) {
            dataSource = DataSourceLocator.newInstance().getDataSource(allInOneName);
            DataSource exist = dalDataSourceMap.putIfAbsent(allInOneName, dataSource);
            dataSource = (exist != null) ? exist : dataSource;
        }

        return dataSource;
    }
}
