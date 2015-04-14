/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.converter;

import com.ctrip.infosec.common.model.RiskFact;
import java.util.Map;

/**
 * 字段转换器，用作预处理
 *
 * @author zhengbaiyun
 */
public interface Converter {

    /**
     *
     * @param preAction 预处理类型
     * @param fieldMapping 接口字段与event中实际字段名称的映射
     * @param fact 事件
     * @param resultWrapper 返回值的字段名
     * @throws java.lang.Exception
     */
    public void convert(PreActionEnums preAction, Map fieldMapping, RiskFact fact, String resultWrapper) throws Exception;
}
