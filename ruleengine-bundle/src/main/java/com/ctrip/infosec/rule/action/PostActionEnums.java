/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.action;

import com.google.common.collect.Maps;
import java.util.Map;

/**
 * 后处理动作枚举
 *
 * @author zhengby
 */
public enum PostActionEnums {

    FrozenAccount("冻结钱包账号", "uid");
    /**
     *
     */
    private String label;
    private String[] fields;
    private static Map<String, PostActionEnums> valueMap = Maps.newHashMap();

    static {
        for (PostActionEnums item : PostActionEnums.values()) {
            valueMap.put(item.toString(), item);
        }
    }

    private PostActionEnums(String label, String... fields) {
        this.label = label;
        this.fields = fields;
    }

    public static PostActionEnums parse(String value) {
        return valueMap.get(value);
    }

    public String getLabel() {
        return label;
    }

    public String[] getFields() {
        return fields;
    }

}
