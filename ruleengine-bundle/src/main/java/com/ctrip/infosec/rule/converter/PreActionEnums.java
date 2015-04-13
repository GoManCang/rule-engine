/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

/**
 * 预处理枚举
 *
 * @author zhengby
 */
public enum PreActionEnums {

    Ip2ProvinceCity("IP转省市", "ip"),
    Mobile2ProvinceCity("手机号转省市", "mobile"),
    UserProfileTags("获取UserProfile标签值", "uid", "tags"),
    CrmUserInfo("获取CRM用户信息", "uid"),
    CardInfoDecrypt("银行卡解密（CardInfo）", "cardInfoId"),
    Airport3Code2City("机场三字码转城市", "airport3code");
    /**
     *
     */
    private String label;
    private String[] fields;

    private PreActionEnums(String label, String... fields) {
        this.label = label;
        this.fields = fields;
    }

    public String getLabel() {
        return label;
    }

    public String[] getFields() {
        return fields;
    }

}
