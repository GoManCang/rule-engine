/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.resource;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLogger;
import com.ctrip.infosec.configs.rule.trace.logger.TraceLoggerHeader;
import static com.ctrip.infosec.configs.utils.Utils.JSON;
import com.ctrip.infosec.counter.enums.ErrorCode;
import com.ctrip.infosec.counter.enums.FlowAccuracy;
import com.ctrip.infosec.counter.model.DecisionDataPushResponse;
import com.ctrip.infosec.counter.model.DecisionDataQueryResponse;
import com.ctrip.infosec.counter.model.DecisionDataRemoveResponse;
import com.ctrip.infosec.counter.model.FlowPushRequest;
import com.ctrip.infosec.counter.model.FlowPushRequest2;
import com.ctrip.infosec.counter.model.FlowPushResponse;
import com.ctrip.infosec.counter.model.FlowQueryRequest;
import com.ctrip.infosec.counter.model.FlowQueryResponse;
import com.ctrip.infosec.counter.model.GetDataFieldListResponse;
import com.ctrip.infosec.counter.model.PolicyExecuteRequest;
import com.ctrip.infosec.counter.model.PolicyExecuteResponse;
import com.ctrip.infosec.counter.venus.DecisionDataRemoteService;
import com.ctrip.infosec.counter.venus.FlowPolicyRemoteServiceV2;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.hystrix.CounterExecuteCommand;
import com.ctrip.infosec.rule.resource.hystrix.CounterQueryFlowDataCommand;
import com.ctrip.infosec.sars.util.GlobalConfig;
import com.ctrip.infosec.sars.util.SpringContextHolder;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.Validate;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author zhengby
 */
public class Counter {

    private static final Logger logger = LoggerFactory.getLogger(Counter.class);
    /**
     * URL前缀, 包含ContextPath部分, 如: http://10.2.10.75:8080/counterws
     */
    static final String urlPrefix = GlobalConfig.getString("Counter.REST.URL.Prefix");

    static void check() {
        Validate.notEmpty(urlPrefix, "在GlobalConfig.properties里没有找到\"Counter.REST.URL.Prefix\"配置项.");
    }

    /**
     * 根据业务编号查询数据字段列表
     *
     * @param bizNo 业务编号
     * @return
     */
    public static GetDataFieldListResponse datafieldList(String bizNo) {
        check();
        GetDataFieldListResponse response = null;
        try {
            String responseTxt = Request.Post(urlPrefix + "/rest/configs/datafieldList")
                    .bodyForm(Form.form()
                            .add("bizNo", bizNo)
                            .build(), Charset.forName("UTF-8"))
                    .execute().returnContent().asString();
            response = JSON.parseObject(responseTxt, GetDataFieldListResponse.class);
        } catch (Exception ex) {
            logger.error(Contexts.getLogPrefix() + "invoke Counter.datafieldList fault.", ex);
            response = new GetDataFieldListResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        }
        return response;
    }

    /**
     * 推送流量数据
     *
     * @param bizNo 业务编号
     * @param kvData 交易数据
     * @return
     */
    public static FlowPushResponse push(String bizNo, Map<String, ?> kvData) {
        check();
        beforeInvoke("Counter.push");
        FlowPushResponse response = null;
        try {
            FlowPushRequest flowPushRequest = new FlowPushRequest();
            flowPushRequest.setBizNo(bizNo);
            flowPushRequest.setKvData(kvData);

            // TraceLogger
            if (StringUtils.isNotBlank(TraceLogger.getEventId())
                    && StringUtils.isNotBlank(TraceLogger.getTransId())) {

                TraceLoggerHeader header = new TraceLoggerHeader();
                header.setEventId(TraceLogger.getEventId());
                if (TraceLogger.hasNestedTrans()) {
                    header.setParentTransId(TraceLogger.getNestedTransId());
                } else {
                    header.setParentTransId(TraceLogger.getTransId());
                }
                flowPushRequest.setTraceLoggerHeader(header);
            }

            if (Contexts.isAsync()) {
                String responseTxt = Request.Post(urlPrefix + "/rest/push")
                        .addHeader("Content-Type", "application/json")
                        .addHeader("Accept-Encoding", "utf-8")
                        .bodyString(JSON.toJSONString(flowPushRequest), ContentType.APPLICATION_JSON)
                        .connectTimeout(1000)
                        .socketTimeout(1000)
                        .execute().returnContent().asString();
                response = JSON.parseObject(responseTxt, FlowPushResponse.class);
            } else {
                FlowPolicyRemoteServiceV2 flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteServiceV2.class);
                response = flowPolicyRemoteService.push(flowPushRequest);
            }

        } catch (Exception ex) {
            fault("Counter.push");
            logger.error(Contexts.getLogPrefix() + "invoke Counter.push fault.", ex);
            response = new FlowPushResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.push");
        }
        return response;
    }

    /**
     * 推送流量数据
     *
     * @param bizNo 业务编号
     * @param kvData 交易数据
     * @return
     */
    public static FlowPushResponse pushToFlow(String bizNo, List<String> flowNoList, Map<String, ?> kvData) {
        check();
        beforeInvoke("Counter.pushToFlow");
        FlowPushResponse response = null;
        try {
            FlowPushRequest2 flowPushRequest = new FlowPushRequest2();
            flowPushRequest.setBizNo(bizNo);
            flowPushRequest.setFlowNoList(flowNoList);
            flowPushRequest.setKvData(kvData);

            // TraceLogger
            if (StringUtils.isNotBlank(TraceLogger.getEventId())
                    && StringUtils.isNotBlank(TraceLogger.getTransId())) {

                TraceLoggerHeader header = new TraceLoggerHeader();
                header.setEventId(TraceLogger.getEventId());
                if (TraceLogger.hasNestedTrans()) {
                    header.setParentTransId(TraceLogger.getNestedTransId());
                } else {
                    header.setParentTransId(TraceLogger.getTransId());
                }
                flowPushRequest.setTraceLoggerHeader(header);
            }

            if (Contexts.isAsync()) {
                String responseTxt = Request.Post(urlPrefix + "/rest/pushToFlow")
                        .addHeader("Content-Type", "application/json")
                        .addHeader("Accept-Encoding", "utf-8")
                        .bodyString(JSON.toJSONString(flowPushRequest), ContentType.APPLICATION_JSON)
                        .connectTimeout(1000)
                        .socketTimeout(1000)
                        .execute().returnContent().asString();
                response = JSON.parseObject(responseTxt, FlowPushResponse.class);
            } else {
                FlowPolicyRemoteServiceV2 flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteServiceV2.class);
                response = flowPolicyRemoteService.pushToFlow(flowPushRequest);
            }

        } catch (Exception ex) {
            fault("Counter.pushToFlow");
            logger.error(Contexts.getLogPrefix() + "invoke Counter.pushToFlow fault.", ex);
            response = new FlowPushResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.pushToFlow");
        }
        return response;
    }

    /**
     * 执行指定策略
     *
     * @param policyNo 策略编号
     * @param kvData 交易数据
     * @return
     */
    public static PolicyExecuteResponse execute(String policyNo, Map<String, ?> kvData) {
        check();
        beforeInvoke("Counter.execute");
        PolicyExecuteResponse response = null;
        try {
            PolicyExecuteRequest policyExecuteRequest = new PolicyExecuteRequest();
            policyExecuteRequest.setPolicyNo(policyNo);
            policyExecuteRequest.setKvData(kvData);

            // TraceLogger
            if (StringUtils.isNotBlank(TraceLogger.getEventId())
                    && StringUtils.isNotBlank(TraceLogger.getTransId())) {

                TraceLoggerHeader header = new TraceLoggerHeader();
                header.setEventId(TraceLogger.getEventId());
                if (TraceLogger.hasNestedTrans()) {
                    header.setParentTransId(TraceLogger.getNestedTransId());
                } else {
                    header.setParentTransId(TraceLogger.getTransId());
                }
                policyExecuteRequest.setTraceLoggerHeader(header);
            }

//            if (Contexts.isAsync()) {
//                String responseTxt = Request.Post(urlPrefix + "/rest/execute")
//                        .addHeader("Content-Type", "application/json")
//                        .addHeader("Accept-Encoding", "utf-8")
//                        .bodyString(JSON.toJSONString(policyExecuteRequest), ContentType.APPLICATION_JSON)
//                        .connectTimeout(1000)
//                        .socketTimeout(5000)
//                        .execute().returnContent().asString();
//                response = JSON.parseObject(responseTxt, PolicyExecuteResponse.class);
//            } else {
//                FlowPolicyRemoteServiceV2 flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteServiceV2.class);
//                response = flowPolicyRemoteService.execute(policyExecuteRequest);
//            }
            CounterExecuteCommand command = new CounterExecuteCommand(policyExecuteRequest, Contexts.isAsync());
            response = command.execute();

        } catch (Exception ex) {
            fault("Counter.execute");
            logger.error(Contexts.getLogPrefix() + "执行Counter.execute超时或异常.", ex);
            response = new PolicyExecuteResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.execute");
        }
        return response;
    }

    /**
     * 查询指定编号的流量数据（不会执行策略）
     *
     * @param flowNo 流量编号
     * @param fieldName 统计项字段名
     * @param accuracy 统计精度
     * @param timeWindow 时间窗口
     * @param kvData 交易数据(至少需要包含维度数据)
     * @return
     */
    public static FlowQueryResponse queryFlowData(String flowNo, String fieldName, FlowAccuracy accuracy, String timeWindow, Map<String, ?> kvData) {
        FlowQueryRequest flowQueryRequest = new FlowQueryRequest();
        flowQueryRequest.setFlowNo(flowNo);
        flowQueryRequest.setFieldName(fieldName);
        flowQueryRequest.setAccuracy(accuracy);
        flowQueryRequest.setTimeWindow(timeWindow);
        flowQueryRequest.setKvData(kvData);
        flowQueryRequest.setQueryMode(0);
        flowQueryRequest.setIncludeCurrentValue(false);
        return queryFlowData(flowQueryRequest);
    }

    public static FlowQueryResponse queryFlowData(FlowQueryRequest flowQueryRequest) {
        check();
        beforeInvoke("Counter.queryFlowData");
        FlowQueryResponse response = null;
        try {

            // TraceLogger
            if (StringUtils.isNotBlank(TraceLogger.getEventId())
                    && StringUtils.isNotBlank(TraceLogger.getTransId())) {

                TraceLoggerHeader header = new TraceLoggerHeader();
                header.setEventId(TraceLogger.getEventId());
                if (TraceLogger.hasNestedTrans()) {
                    header.setParentTransId(TraceLogger.getNestedTransId());
                } else {
                    header.setParentTransId(TraceLogger.getTransId());
                }
                flowQueryRequest.setTraceLoggerHeader(header);
            }

            // PolicyOrRuleNo
            if (StringUtils.isNotBlank(Contexts.getPolicyOrRuleNo())) {
                flowQueryRequest.setPolicyOrRuleNo(Contexts.getPolicyOrRuleNo());
            }

//            if (Contexts.isAsync()) {
//                String responseTxt = Request.Post(urlPrefix + "/rest/queryFlowData")
//                        .addHeader("Content-Type", "application/json")
//                        .addHeader("Accept-Encoding", "utf-8")
//                        .bodyString(JSON.toJSONString(flowQueryRequest), ContentType.APPLICATION_JSON)
//                        .connectTimeout(1000)
//                        .socketTimeout(5000)
//                        .execute().returnContent().asString();
//                response = JSON.parseObject(responseTxt, FlowQueryResponse.class);
//            } else {
//                FlowPolicyRemoteServiceV2 flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteServiceV2.class);
//                response = flowPolicyRemoteService.queryFlowData(flowQueryRequest);
//            }
            CounterQueryFlowDataCommand command = new CounterQueryFlowDataCommand(flowQueryRequest, true);
            response = command.execute();

        } catch (Exception ex) {
            fault("Counter.queryFlowData");
            logger.error(Contexts.getLogPrefix() + "执行Counter.queryFlowData超时或异常.", ex);
            response = new FlowQueryResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.queryFlowData");
        }
        return response;
    }

    /**
     * 决策表数据推送接口
     *
     * @param decisionTableNo 决策表编号
     * @param xData 决策表横坐标数据
     * @param yData 决策表纵坐标数据
     * @param expireAt 数据失效时间, null表示永不过期
     * @param memo 描述
     * @return
     */
    public static DecisionDataPushResponse pushDecisionData(String decisionTableNo, Map<String, String> xData, Map<String, String> yData, Date expireAt, String memo) {
        check();
        beforeInvoke("Counter.pushDecisionData");
        DecisionDataPushResponse response = null;
        try {
            DecisionDataRemoteService decisionDataRemoteService = SpringContextHolder.getBean(DecisionDataRemoteService.class);
            response = decisionDataRemoteService.pushDecisionData(decisionTableNo, xData, yData, expireAt, memo);
        } catch (Exception ex) {
            fault("Counter.pushDecisionData");
            logger.error(Contexts.getLogPrefix() + "invoke Counter.pushDecisionData fault.", ex);
            response = new DecisionDataPushResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.pushDecisionData");
        }
        return response;
    }

    /**
     * 决策表数据删除接口
     *
     * @param decisionTableNo 决策表编号
     * @param xData 决策表横坐标数据
     * @return 返回结果中包含删除的记录数
     */
    public static DecisionDataRemoveResponse removeDecisionData(String decisionTableNo, Map<String, String> xData) {
        check();
        beforeInvoke("Counter.pushDecisionData");
        DecisionDataRemoveResponse response = null;
        try {
            DecisionDataRemoteService decisionDataRemoteService = SpringContextHolder.getBean(DecisionDataRemoteService.class);
            response = decisionDataRemoteService.removeDecisionData(decisionTableNo, xData);
        } catch (Exception ex) {
            fault("Counter.pushDecisionData");
            logger.error(Contexts.getLogPrefix() + "invoke Counter.removeDecisionData fault.", ex);
            response = new DecisionDataRemoveResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.removeDecisionData");
        }
        return response;
    }

    /**
     * 决策表数据查询接口
     *
     * @param decisionTableNo 决策表编号
     * @param xData 决策表横坐标数据
     * @return 返回决策表纵坐标数据
     */
    public static DecisionDataQueryResponse queryDecisionData(String decisionTableNo, Map<String, String> xData) {
        check();
        beforeInvoke("Counter.pushDecisionData");
        DecisionDataQueryResponse response = null;
        try {
            DecisionDataRemoteService decisionDataRemoteService = SpringContextHolder.getBean(DecisionDataRemoteService.class);
            response = decisionDataRemoteService.queryDecisionData(decisionTableNo, xData);
        } catch (Exception ex) {
            fault("Counter.pushDecisionData");
            logger.error(Contexts.getLogPrefix() + "invoke Counter.queryDecisionData fault.", ex);
            response = new DecisionDataQueryResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.queryDecisionData");
        }
        return response;
    }

}
