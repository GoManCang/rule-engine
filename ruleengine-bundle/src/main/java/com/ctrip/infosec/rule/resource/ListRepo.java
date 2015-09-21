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
import com.ctrip.infosec.counter.venus.ListRepoRemoteService;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import java.util.List;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 名单库服务（单级）
 *
 * @author zhengby
 */
public class ListRepo {

    private static final Logger logger = LoggerFactory.getLogger(ListRepo.class);
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
    public static ListRepoResponse put(String repo, String value, int ttl, String memo) {
        check();
        beforeInvoke("ListRepo.put");
        ListRepoResponse response = null;
        try {
            ListRepoRemoteService listRepoRemoteService = SpringContextHolder.getBean(ListRepoRemoteService.class);
            response = listRepoRemoteService.put(repo, value, ttl, memo);
        } catch (Exception ex) {
            fault("ListRepo.put");
            logger.error(Contexts.getLogPrefix() + "invoke ListRepo.put fault.", ex);
            response = new ListRepoResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ListRepo.put");
        }
        return response;
    }

    public static ListRepoResponse putIfNotExists(String repo, String value, int ttl, String memo) {
        check();
        beforeInvoke("ListRepo.putIfNotExists");
        ListRepoResponse response = null;
        try {
            ListRepoRemoteService listRepoRemoteService = SpringContextHolder.getBean(ListRepoRemoteService.class);
            response = listRepoRemoteService.putIfNotExists(repo, value, ttl, memo);
        } catch (Exception ex) {
            fault("ListRepo.putIfNotExists");
            logger.error(Contexts.getLogPrefix() + "invoke ListRepo.putIfNotExists fault.", ex);
            response = new ListRepoResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ListRepo.putIfNotExists");
        }
        return response;
    }

    public static ListRepoResponse remove(String repo, String value) {
        check();
        beforeInvoke("ListRepo.remove");
        ListRepoResponse response = null;
        try {
            ListRepoRemoteService listRepoRemoteService = SpringContextHolder.getBean(ListRepoRemoteService.class);
            response = listRepoRemoteService.remove(repo, value);
        } catch (Exception ex) {
            fault("ListRepo.remove");
            logger.error(Contexts.getLogPrefix() + "invoke ListRepo.remove fault.", ex);
            response = new ListRepoResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ListRepo.remove");
        }
        return response;
    }

    public static ListRepoBooleanResponse isIn(String repo, String value) {
        check();
        beforeInvoke("ListRepo.isIn");
        ListRepoBooleanResponse response = null;
        try {
            ListRepoRemoteService listRepoRemoteService = SpringContextHolder.getBean(ListRepoRemoteService.class);
            response = listRepoRemoteService.isIn(repo, value);
        } catch (Exception ex) {
            fault("ListRepo.isIn");
            logger.error(Contexts.getLogPrefix() + "invoke ListRepo.isIn fault.", ex);
            response = new ListRepoBooleanResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ListRepo.isIn");
        }
        return response;
    }

    public static ListRepoBooleanResponse isAnyIn(String repo, List<String> values) {
        check();
        beforeInvoke("ListRepo.isAnyIn");
        ListRepoBooleanResponse response = null;
        try {
            ListRepoRemoteService listRepoRemoteService = SpringContextHolder.getBean(ListRepoRemoteService.class);
            response = listRepoRemoteService.isAnyIn(repo, values);
        } catch (Exception ex) {
            fault("ListRepo.isAnyIn");
            logger.error(Contexts.getLogPrefix() + "invoke ListRepo.isAnyIn fault.", ex);
            response = new ListRepoBooleanResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ListRepo.isAnyIn");
        }
        return response;
    }

    public static ListRepoBooleanResponse isAllIn(String repo, List<String> values) {
        check();
        beforeInvoke("ListRepo.isAllIn");
        ListRepoBooleanResponse response = null;
        try {
            ListRepoRemoteService listRepoRemoteService = SpringContextHolder.getBean(ListRepoRemoteService.class);
            response = listRepoRemoteService.isAllIn(repo, values);
        } catch (Exception ex) {
            fault("ListRepo.isAllIn");
            logger.error(Contexts.getLogPrefix() + "invoke ListRepo.isAllIn fault.", ex);
            response = new ListRepoBooleanResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("ListRepo.isAllIn");
        }
        return response;
    }
}
