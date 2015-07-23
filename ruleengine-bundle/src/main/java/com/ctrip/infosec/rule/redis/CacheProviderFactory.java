/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.redis;

import com.ctrip.infosec.sars.util.GlobalConfig;
import com.google.common.collect.Maps;
import credis.java.client.CacheProvider;
import credis.java.client.setting.RAppSetting;
import credis.java.client.util.CacheFactory;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author zhengby
 */
public class CacheProviderFactory {

    private static final Logger logger = LoggerFactory.getLogger(CacheProviderFactory.class);
    /**
     * Redis Cluster
     */
    private static Map<String, CacheProvider> clusters = Maps.newConcurrentMap();
    private static Lock lock = new ReentrantLock();

    public static CacheProvider getCacheProvider(String clusterName) {
        CacheProvider cluster = clusters.get(clusterName);
        if (cluster == null) {
            lock.lock();
            try {
                cluster = clusters.get(clusterName);
                if (cluster == null) {
                    try {
                        // Setting
                        buildRAppSetting();
                        logger.warn("连接CRedis集群, clusterName=" + clusterName + " ...");
                        cluster = CacheFactory.GetProvider(clusterName);
                        logger.warn("连接CRedis集群, clusterName=" + clusterName + " ... OK");
                        clusters.put(clusterName, cluster);
                    } catch (Exception ex) {
                        logger.error("连接CRedis集群异常. clusterName=" + clusterName, ex);
                    }
                }
            } finally {
                lock.unlock();
            }
        }
        return cluster;
    }

    static void buildRAppSetting() {
        String appId = GlobalConfig.getString("appId");
        String cRedisServiceUrl = GlobalConfig.getString("CRedis.serviceUrl");
        boolean isLogging = GlobalConfig.getBoolean("CRedis.logging", false);
        String loggingServerIP = GlobalConfig.getString("CLogging.serverIp");
        String loggingServerPort = GlobalConfig.getString("CLogging.serverPort");

        RAppSetting.setAppID(appId); // AppId
        RAppSetting.setCRedisServiceUrl(cRedisServiceUrl);
        RAppSetting.setLogging(isLogging);
        RAppSetting.setLoggingServerIP(loggingServerIP);
        RAppSetting.setLoggingServerPort(loggingServerPort);
    }
}
