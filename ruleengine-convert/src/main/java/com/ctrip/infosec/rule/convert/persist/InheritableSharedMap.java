package com.ctrip.infosec.rule.convert.persist;

import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;

import java.util.Deque;
import java.util.LinkedList;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/23.
 */
public class InheritableSharedMap {
    private LinkedList<Map<String, Object>> stack = new LinkedList<Map<String, Object>>();
    private Map<String, Object> currentMap = null;

    public InheritableSharedMap() {
        currentMap = Maps.newHashMap();
    }

    public void enterChild() {
        stack.add(currentMap);
        currentMap = Maps.newHashMap();
    }

    public void returnFromChild() {
        currentMap = stack.pollLast();
    }

    public Object getValue(String varName) {
        Map<String, Object> map = currentMap;
        Object o = map.get(varName);
        if (o != null) {
            return o;
        }
        int pos = stack.size();
        if (pos > 0) {
            for (; pos > 0; pos--) {
                map = stack.get(pos - 1);
                o = map.get(varName);
                if (o != null) {
                    return o;
                }
            }
        }
        return null;
    }

    public void addSharedValues(String prefix, Map<String, Object> sharedValues) {
        if (StringUtils.isBlank(prefix)) {
            currentMap.putAll(sharedValues);
        } else {
            for (Map.Entry<String, Object> entry : sharedValues.entrySet()) {
                currentMap.put(prefix + "." + entry.getKey(), entry.getValue());
            }
        }
    }
}
