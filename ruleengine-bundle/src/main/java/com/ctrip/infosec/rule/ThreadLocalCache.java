/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author zhengby
 */
public class ThreadLocalCache {

    /**
     * 线程缓存（用于优化预处理）
     */
    private static ThreadLocal<Map<String, Object>> _tcache = new ThreadLocal<Map<String, Object>>() {
        @Override
        protected Map<String, Object> initialValue() {
            return new HashMap<String, Object>();
        }
    };

    public static void set(String key, Object obj) {
        ThreadLocalCache._tcache.get().put(key, obj);
    }

    public static Object get(String key) {
        return ThreadLocalCache._tcache.get().get(key);
    }

    public static void clear() {
        ThreadLocalCache._tcache.get().clear();
    }
}
