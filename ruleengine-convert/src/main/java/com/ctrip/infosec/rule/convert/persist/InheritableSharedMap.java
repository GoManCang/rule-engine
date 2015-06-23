package com.ctrip.infosec.rule.convert.persist;

import com.google.common.collect.Maps;

import java.util.Deque;
import java.util.LinkedList;
import java.util.Map;

/**
 * Created by yxjiang on 2015/6/23.
 */
public class InheritableSharedMap {
    private Deque<Map<String, Object>> stack = new LinkedList<Map<String, Object>>();
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

    public Map<String, Object> getCurrentMap(){
        return currentMap;
    }
}
