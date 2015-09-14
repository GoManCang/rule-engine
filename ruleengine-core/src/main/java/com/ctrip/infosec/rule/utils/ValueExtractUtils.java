package com.ctrip.infosec.rule.utils;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.math.NumberUtils;

import java.util.Map;

/**
 * Created by yxjiang on 2015/9/10.
 */
public class ValueExtractUtils {
    private static Converter<Long> longConverter = new LongConverter(-1L);
    private static Converter<Integer> integerConverter = new IntegerConverter(-1);

    public static Long extractLongIgnoreCase(Map<String, ?> map, String key) {
        return extractIgnoreCase(map, key, longConverter);
    }

    public static Integer extractIntegerIgnoreCase(Map<String, ?> map, String key) {
        return extractIgnoreCase(map, key, integerConverter);
    }

    public static <R> R extractIgnoreCase(Map<String, ?> map, String key, Converter<R> converter) {
        if (MapUtils.isNotEmpty(map)) {
            if (map.containsKey(key)){
                return converter.convert(map.get(key));
            }
            for (Map.Entry<String, ?> entry : map.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(key)) {
                    return converter.convert(entry.getValue());
                }
            }
        }
        return null;
    }

    interface Converter<R> {
        R convert(Object obj);
    }

    static class LongConverter implements Converter<Long>{
        private Long defaultValue = -1L;
        LongConverter(Long defaultValue){
            this.defaultValue = defaultValue;
        }

        @Override
        public Long convert(Object obj) {
            return NumberUtils.toLong(String.valueOf(obj), defaultValue);
        }
    }

    static class IntegerConverter implements Converter<Integer>{
        private Integer defaultValue = -1;
        IntegerConverter(Integer defaultValue){
            this.defaultValue = defaultValue;
        }
        @Override
        public Integer convert(Object obj) {
            return NumberUtils.toInt(String.valueOf(obj), defaultValue);
        }
    }
}
