package com.ctrip.infosec.rule.convert.util;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ctrip.datasource.locator.DataSourceLocator;

public class DalDataSourceHolder {
	
	private static Logger logger = LoggerFactory.getLogger(DalDataSourceHolder.class);
	
	private static DataSource dalDataSource;

	public static DataSource getDataSource(String allInOneName) throws Exception {
		
		if (null == dalDataSource) 
			dalDataSource = DataSourceLocator.newInstance().getDataSource(allInOneName);
		
		return dalDataSource;
	}
}
