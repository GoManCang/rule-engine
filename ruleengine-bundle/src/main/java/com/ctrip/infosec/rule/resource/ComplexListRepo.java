/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import com.ctrip.infosec.counter.enums.ErrorCode;
import com.ctrip.infosec.counter.model.ListRepoBooleanResponse;
import com.ctrip.infosec.counter.model.ListRepoResponse;
import com.ctrip.infosec.counter.venus.ComplexListRepoRemoteService;
import com.ctrip.infosec.counter.venus.ListRepoRemoteService;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 名单库服务（支持多级）
 *
 * @author zhengby
 */
public class ComplexListRepo {

    private static final Logger logger = LoggerFactory.getLogger(ComplexListRepo.class);
    /**
     * URL前缀, 包含ContextPath部分, 如: http://10.2.10.75:8080/counterws
     */
    static final String urlPrefix = GlobalConfig.getString("Counter.REST.URL.Prefix");

    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"Counter.REST.URL.Prefix\"配置项.");
    }

    /**
     * 放入名单库
     *
     * @param repo 名单库名称
     * @param value 值
     * @param ttl 失效时间, 秒, 0表示永不过期
     * @param memo 描述
     * @return
     */
    public static ListRepoResponse put(String repo, Map<String, String> value, int ttl, String memo) {
        check();
        beforeInvoke();
        ListRepoResponse response = null;
        try {
            ComplexListRepoRemoteService complexListRepoRemoteService = SpringContextHolder.getBean(ComplexListRepoRemoteService.class);
            response = complexListRepoRemoteService.put(repo, value, ttl, memo);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke ComplexListRepo.put fault.", ex);
            response = new ListRepoResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ComplexListRepo.put");
        }
        return response;
    }

    public static ListRepoResponse putIfNotExists(String repo, Map<String, String> value, int ttl, String memo) {
        check();
        beforeInvoke();
        ListRepoResponse response = null;
        try {
            ComplexListRepoRemoteService complexListRepoRemoteService = SpringContextHolder.getBean(ComplexListRepoRemoteService.class);
            response = complexListRepoRemoteService.putIfNotExists(repo, value, ttl, memo);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke ComplexListRepo.putIfNotExists fault.", ex);
            response = new ListRepoResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ComplexListRepo.putIfNotExists");
        }
        return response;
    }

    public static ListRepoResponse remove(String repo, Map<String, String> value) {
        check();
        beforeInvoke();
        ListRepoResponse response = null;
        try {
            ComplexListRepoRemoteService complexListRepoRemoteService = SpringContextHolder.getBean(ComplexListRepoRemoteService.class);
            response = complexListRepoRemoteService.remove(repo, value);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke ComplexListRepo.remove fault.", ex);
            response = new ListRepoResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ComplexListRepo.remove");
        }
        return response;
    }

    public static ListRepoBooleanResponse isIn(String repo, Map<String, String> value) {
        check();
        beforeInvoke();
        ListRepoBooleanResponse response = null;
        try {
            ComplexListRepoRemoteService complexListRepoRemoteService = SpringContextHolder.getBean(ComplexListRepoRemoteService.class);
            response = complexListRepoRemoteService.isIn(repo, value);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke ComplexListRepo.isIn fault.", ex);
            response = new ListRepoBooleanResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ComplexListRepo.isIn");
        }
        return response;
    }

    public static ListRepoBooleanResponse isAnyIn(String repo, List<Map<String, String>> values) {
        check();
        beforeInvoke();
        ListRepoBooleanResponse response = null;
        try {
            ComplexListRepoRemoteService complexListRepoRemoteService = SpringContextHolder.getBean(ComplexListRepoRemoteService.class);
            response = complexListRepoRemoteService.isAnyIn(repo, values);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke ComplexListRepo.isAnyIn fault.", ex);
            response = new ListRepoBooleanResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ComplexListRepo.isAnyIn");
        }
        return response;
    }

    public static ListRepoBooleanResponse isAllIn(String repo, List<Map<String, String>> values) {
        check();
        beforeInvoke();
        ListRepoBooleanResponse response = null;
        try {
            ComplexListRepoRemoteService complexListRepoRemoteService = SpringContextHolder.getBean(ComplexListRepoRemoteService.class);
            response = complexListRepoRemoteService.isAllIn(repo, values);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke ComplexListRepo.isAllIn fault.", ex);
            response = new ListRepoBooleanResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ComplexListRepo.isAllIn");
        }
        return response;
    }
}
