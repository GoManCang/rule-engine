package com.ctrip.infosec.rule.convert.util;

import org.apache.commons.lang.time.DateUtils;

import java.text.ParseException;
import java.util.Date;

/**
 * Created by yxjiang on 2015/7/16.
 */
public class PersistConvertUtils {
    /**
     * 解析日期支持格式为：
     * <ul>
     *     <li>yyyy-MM-dd HH:mm:ss.SSS</li>
     *     <li>yyyy-MM-dd HH:mm:ss</li>
     *     <li>yyyy-MM-dd'T'HH:mm:ss</li>
     *     <li>yyyy-MM-dd</li>
     * </ul>
     * @param str
     * @return
     * @throws ParseException
     */
    public static Date parseDate(String str) throws ParseException {
        return DateUtils.parseDate(str, new String[]{"yyyy-MM-dd HH:mm:ss.SSS", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd"});
    }

}
