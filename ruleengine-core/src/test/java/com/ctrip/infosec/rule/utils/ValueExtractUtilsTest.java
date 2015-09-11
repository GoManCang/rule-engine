package com.ctrip.infosec.rule.utils;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

/**
 * Created by yxjiang on 2015/9/11.
 */
public class ValueExtractUtilsTest {

    @Test
    public void testExtractLongIgnoreCase() throws Exception {
        Map<String, String> map = new HashMap<>();
        map.put("orDer", "1");
        map.put("typE", null);
        assertThat(1, is(ValueExtractUtils.extractIntegerIgnoreCase(map, "order")));
        assertThat(1L, is(ValueExtractUtils.extractLongIgnoreCase(map, "order")));
        assertThat(1L, is(ValueExtractUtils.extractLongIgnoreCase(map, "orDer")));
        assertThat(null, is(ValueExtractUtils.extractLongIgnoreCase(map, "or")));
        assertThat(-1L, is(ValueExtractUtils.extractLongIgnoreCase(map, "Type")));
        assertThat(-1, is(ValueExtractUtils.extractIntegerIgnoreCase(map, "Type")));

    }

}