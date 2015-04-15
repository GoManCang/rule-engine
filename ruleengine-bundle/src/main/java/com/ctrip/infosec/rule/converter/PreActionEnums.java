/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.google.common.collect.Maps;
import java.util.Map;

/**
 * 预处理枚举
 *
 * @author zhengby
 */
public enum PreActionEnums {

    Ip2ProvinceCity(
            "IP转省市",
            new PreActionParam("ip", PreActionParam.FIELD)),
    Mobile2ProvinceCity(
            "手机号转省市",
            new PreActionParam("mobile", PreActionParam.FIELD)),
    UserProfileTags(
            "获取UserProfile标签值",
            new PreActionParam("uid", PreActionParam.FIELD),
            new PreActionParam("tags", PreActionParam.TEXT)), // tags需要手动输入、不是从eventBody里获取
    CrmMemberInfo(
            "获取CRM会员信息",
            new PreActionParam("uid", PreActionParam.FIELD)),
    CardInfoDecrypt(
            "银行卡解密（CardInfo）",
            new PreActionParam("cardInfoId", PreActionParam.FIELD)),
    Airport3Code2City(
            "机场三字码转城市",
            new PreActionParam("airport3code", PreActionParam.FIELD));

    /**
     *
     */
    private String label;
    private PreActionParam[] fields;
    private static Map<String, PreActionEnums> valueMap = Maps.newHashMap();

    static {
        for (PreActionEnums item : PreActionEnums.values()) {
            valueMap.put(item.toString(), item);
        }
    }

    private PreActionEnums(String label, PreActionParam... fields) {
        this.label = label;
        this.fields = fields;
    }

    public static PreActionEnums parse(String value) {
        return valueMap.get(value);
    }

    public String getLabel() {
        return label;
    }

    public PreActionParam[] getFields() {
        return fields;
    }

}
