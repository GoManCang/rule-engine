/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import com.ctrip.infosec.configs.utils.Threads;
import com.ctrip.infosec.counter.model.ListRepoBooleanResponse;
import com.ctrip.infosec.counter.model.ListRepoResponse;
import com.google.common.collect.Lists;
import com.meidusa.fastjson.JSON;
import java.util.concurrent.TimeUnit;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author zhengby
 */
//@Ignore
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:spring/counter-venus-test.xml"})
public class ListRepoTest {

    /**
     * Test of put method, of class ListRepo.
     */
    @Test
    public void testPut() {
        System.out.println("put");
        ListRepoResponse response = ListRepo.put("L0001001", "hello world!", 3, "my test value");
        System.out.println("response: " + JSON.toJSONString(response));
        assertEquals(response.getErrorCode(), "0");

        ListRepoBooleanResponse booleanResponse = ListRepo.isIn("L0001001", "hello world!");
        System.out.println("booleanResponse: " + JSON.toJSONString(booleanResponse));
        assertEquals(booleanResponse.getErrorCode(), "0");
        assertTrue(booleanResponse.getResult());

        Threads.sleep(4, TimeUnit.SECONDS);
        booleanResponse = ListRepo.isIn("L0001001", "hello world!");
        assertEquals(booleanResponse.getErrorCode(), "0");
        assertTrue(booleanResponse.getResult() == false);
    }

    /**
     * Test of putIfNotExists method, of class ListRepo.
     */
    @Test
    public void testPutIfNotExists() {
        System.out.println("putIfNotExists");
        ListRepoResponse response = ListRepo.putIfNotExists("L0001001", "hello world!", 3, "my test value");
        System.out.println("response: " + JSON.toJSONString(response));
        assertEquals(response.getErrorCode(), "0");

        ListRepoBooleanResponse booleanResponse = ListRepo.isIn("L0001001", "hello world!");
        System.out.println("booleanResponse: " + JSON.toJSONString(booleanResponse));
        assertEquals(booleanResponse.getErrorCode(), "0");
        assertTrue(booleanResponse.getResult());

        Threads.sleep(4, TimeUnit.SECONDS);
        booleanResponse = ListRepo.isIn("L0001001", "hello world!");
        System.out.println("booleanResponse: " + JSON.toJSONString(booleanResponse));
        assertEquals(booleanResponse.getErrorCode(), "0");
        assertTrue(booleanResponse.getResult() == false);
    }

    /**
     * Test of remove method, of class ListRepo.
     */
    @Test
    public void testRemove() {
        System.out.println("remove");
        ListRepoResponse response = ListRepo.putIfNotExists("L0001001", "hello world!", 3, "my test value");
        System.out.println("response: " + JSON.toJSONString(response));
        assertEquals(response.getErrorCode(), "0");

        response = ListRepo.remove("L0001001", "hello world!");
        System.out.println("response: " + JSON.toJSONString(response));
        assertEquals(response.getErrorCode(), "0");

        ListRepoBooleanResponse booleanResponse = ListRepo.isIn("L0001001", "hello world!");
        System.out.println("booleanResponse: " + JSON.toJSONString(booleanResponse));
        assertEquals(booleanResponse.getErrorCode(), "0");
        assertTrue(booleanResponse.getResult() == false);
    }

    /**
     * Test of isAnyIn method, of class ListRepo.
     */
    @Test
    public void testIsAnyIn() {
        System.out.println("isAnyIn");
        ListRepo.put("L0001001", "hello world! - 1", 3, "my test value");
        ListRepo.put("L0001001", "hello world! - 2", 3, "my test value");

        ListRepoBooleanResponse booleanResponse = ListRepo.isAnyIn("L0001001", Lists.newArrayList("hello world!", "hello world! - 1"));
        System.out.println("booleanResponse: " + JSON.toJSONString(booleanResponse));
        assertEquals(booleanResponse.getErrorCode(), "0");
        assertTrue(booleanResponse.getResult());
    }

    /**
     * Test of isAllIn method, of class ListRepo.
     */
    @Test
//    @Ignore
    public void testIsAllIn() {
        System.out.println("isAllIn");
        ListRepo.put("L0001001", "hello world! - 1", 3, "my test value");
        ListRepo.put("L0001001", "hello world! - 2", 3, "my test value");

        ListRepoBooleanResponse booleanResponse = ListRepo.isAnyIn("L0001001", Lists.newArrayList("hello world!", "hello world! - 1"));
        System.out.println("booleanResponse: " + JSON.toJSONString(booleanResponse));
        assertEquals(booleanResponse.getErrorCode(), "0");
//        assertTrue(booleanResponse.getResult() == false);
    }

}
