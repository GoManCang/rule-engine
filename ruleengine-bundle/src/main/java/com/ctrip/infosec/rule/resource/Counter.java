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
import com.ctrip.infosec.counter.model.FlowPushResponse;
import com.ctrip.infosec.counter.model.FlowQueryResponse;
import com.ctrip.infosec.counter.model.GetDataFieldListResponse;
import com.ctrip.infosec.counter.model.PolicyBatchExecuteResponse;
import com.ctrip.infosec.counter.model.PolicyExecuteRequest;
import com.ctrip.infosec.counter.model.PolicyExecuteResponse;
import com.ctrip.infosec.counter.venus.DecisionDataRemoteService;
import com.ctrip.infosec.counter.venus.FlowPolicyRemoteService;
import com.ctrip.infosec.counter.venus.FlowPolicyRemoteServiceV2;
import com.ctrip.infosec.rule.Contexts;
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
    public static FlowPushResponse push(String bizNo, Map<String, String> kvData) {
        check();
        beforeInvoke();
        FlowPushResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/push")
//                    .bodyForm(Form.form()
//                            .add("bizNo", bizNo)
//                            .add("kvData", JSON.toJSONString(kvData))
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, FlowPushResponse.class);
//            FlowPolicyRemoteService flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteService.class);
            FlowPolicyRemoteServiceV2 flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteServiceV2.class);
//            response = flowPolicyRemoteService.push(bizNo, kvData);
            FlowPushRequest flowPushRequest = new FlowPushRequest();
            flowPushRequest.setBizNo(bizNo);
            flowPushRequest.setKvData(kvData);

            // TraceLogger
            if (StringUtils.isNotBlank(TraceLogger.getEventId())
                    && StringUtils.isNotBlank(TraceLogger.getTransId())) {

                TraceLoggerHeader header = new TraceLoggerHeader();
                header.setEventId(TraceLogger.getEventId());
                header.setParentTransId(TraceLogger.getTransId());
                flowPushRequest.setTraceLoggerHeader(header);
            }

            response = flowPolicyRemoteService.push(flowPushRequest);
        } catch (Exception ex) {
            fault();
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
     * 推送流量数据, 并执行指定策略
     *
     * @param bizNo 业务编号
     * @param policyNo 策略编号
     * @param kvData 交易数据
     * @return
     */
    public static PolicyExecuteResponse pushAndExecute(String bizNo, String policyNo, Map<String, String> kvData) {
        check();
        beforeInvoke();
        PolicyExecuteResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/pushAndExecute")
//                    .bodyForm(Form.form()
//                            .add("bizNo", bizNo)
//                            .add("policyNo", policyNo)
//                            .add("kvData", JSON.toJSONString(kvData))
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, PolicyExecuteResponse.class);
            FlowPolicyRemoteService flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteService.class);
            response = flowPolicyRemoteService.pushAndExecute(bizNo, policyNo, kvData);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke Counter.pushAndExecute fault.", ex);
            response = new PolicyExecuteResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.pushAndExecute");
        }
        return response;
    }

    /**
     * 推送流量数据, 并执行指定策略(多个)
     *
     * @param bizNo 业务编号
     * @param policyNoList 多个策略编号
     * @param kvData 交易数据
     * @return
     */
    public static PolicyBatchExecuteResponse pushAndExecuteAll(String bizNo, List<String> policyNoList, Map<String, String> kvData) {
        check();
        beforeInvoke();
        PolicyBatchExecuteResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/pushAndExecuteAll")
//                    .bodyForm(Form.form()
//                            .add("bizNo", bizNo)
//                            .add("policyNoList", StringUtils.join(policyNoList, ","))
//                            .add("kvData", JSON.toJSONString(kvData))
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, PolicyBatchExecuteResponse.class);
            FlowPolicyRemoteService flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteService.class);
            response = flowPolicyRemoteService.pushAndExecuteAll(bizNo, policyNoList, kvData);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke Counter.pushAndExecuteAll fault.", ex);
            response = new PolicyBatchExecuteResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.pushAndExecuteAll");
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
    public static PolicyExecuteResponse execute(String policyNo, Map<String, String> kvData) {
        check();
        beforeInvoke();
        PolicyExecuteResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/execute")
//                    .bodyForm(Form.form()
//                            .add("policyNo", policyNo)
//                            .add("kvData", JSON.toJSONString(kvData))
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, PolicyExecuteResponse.class);
//            FlowPolicyRemoteService flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteService.class);
            FlowPolicyRemoteServiceV2 flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteServiceV2.class);
//            response = flowPolicyRemoteService.execute(policyNo, kvData);
            PolicyExecuteRequest policyExecuteRequest = new PolicyExecuteRequest();
            policyExecuteRequest.setPolicyNo(policyNo);
            policyExecuteRequest.setKvData(kvData);

            // TraceLogger
            if (StringUtils.isNotBlank(TraceLogger.getEventId())
                    && StringUtils.isNotBlank(TraceLogger.getTransId())) {

                TraceLoggerHeader header = new TraceLoggerHeader();
                header.setEventId(TraceLogger.getEventId());
                header.setParentTransId(TraceLogger.getTransId());
                policyExecuteRequest.setTraceLoggerHeader(header);
            }

            response = flowPolicyRemoteService.execute(policyExecuteRequest);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke Counter.execute fault.", ex);
            response = new PolicyExecuteResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.execute");
        }
        return response;
    }

    /**
     * 执行指定策略(多个)
     *
     * @param policyNoList 多个策略编号
     * @param kvData 交易数据
     * @return
     */
    public static PolicyBatchExecuteResponse executeAll(List<String> policyNoList, Map<String, String> kvData) {
        check();
        beforeInvoke();
        PolicyBatchExecuteResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/executeAll")
//                    .bodyForm(Form.form()
//                            .add("policyNoList", StringUtils.join(policyNoList, ","))
//                            .add("kvData", JSON.toJSONString(kvData))
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, PolicyBatchExecuteResponse.class);
            FlowPolicyRemoteService flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteService.class);
            response = flowPolicyRemoteService.executeAll(policyNoList, kvData);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke Counter.executeAll fault.", ex);
            response = new PolicyBatchExecuteResponse();
            response.setErrorCode(ErrorCode.EXCEPTION.getCode());
            response.setErrorMessage(ex.getMessage());
        } finally {
            afterInvoke("Counter.executeAll");
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
    public static FlowQueryResponse queryFlowData(String flowNo, String fieldName, FlowAccuracy accuracy, String timeWindow, Map<String, String> kvData) {
        check();
        beforeInvoke();
        FlowQueryResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/queryFlowData")
//                    .bodyForm(Form.form()
//                            .add("flowNo", flowNo)
//                            .add("fieldName", fieldName)
//                            .add("accuracy", accuracy.toString())
//                            .add("timeWindow", timeWindow)
//                            .add("kvData", JSON.toJSONString(kvData))
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, FlowQueryResponse.class);
            FlowPolicyRemoteService flowPolicyRemoteService = SpringContextHolder.getBean(FlowPolicyRemoteService.class);
            response = flowPolicyRemoteService.queryFlowData(flowNo, fieldName, accuracy, timeWindow, kvData);
        } catch (Exception ex) {
            fault();
            logger.error(Contexts.getLogPrefix() + "invoke Counter.queryFlowData fault.", ex);
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
        beforeInvoke();
        DecisionDataPushResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/pushDecisionData")
//                    .bodyForm(Form.form()
//                            .add("decisionTableNo", decisionTableNo)
//                            .add("xData", JSON.toJSONString(xData))
//                            .add("yData", JSON.toJSONString(yData))
//                            .add("expireAt", expireAt != null ? fastDateFormat.format(expireAt) : "")
//                            .add("memo", memo)
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, DecisionDataPushResponse.class);
            DecisionDataRemoteService decisionDataRemoteService = SpringContextHolder.getBean(DecisionDataRemoteService.class);
            response = decisionDataRemoteService.pushDecisionData(decisionTableNo, xData, yData, expireAt, memo);
        } catch (Exception ex) {
            fault();
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
        beforeInvoke();
        DecisionDataRemoveResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/removeDecisionData")
//                    .bodyForm(Form.form()
//                            .add("decisionTableNo", decisionTableNo)
//                            .add("xData", JSON.toJSONString(xData))
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, DecisionDataRemoveResponse.class);
            DecisionDataRemoteService decisionDataRemoteService = SpringContextHolder.getBean(DecisionDataRemoteService.class);
            response = decisionDataRemoteService.removeDecisionData(decisionTableNo, xData);
        } catch (Exception ex) {
            fault();
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
        beforeInvoke();
        DecisionDataQueryResponse response = null;
        try {
//            String responseTxt = Request.Post(urlPrefix + "/rest/queryDecisionData")
//                    .bodyForm(Form.form()
//                            .add("decisionTableNo", decisionTableNo)
//                            .add("xData", JSON.toJSONString(xData))
//                            .build(), Charset.forName("UTF-8"))
//                    .execute().returnContent().asString();
//            response = JSON.parseObject(responseTxt, DecisionDataQueryResponse.class);
            DecisionDataRemoteService decisionDataRemoteService = SpringContextHolder.getBean(DecisionDataRemoteService.class);
            response = decisionDataRemoteService.queryDecisionData(decisionTableNo, xData);
        } catch (Exception ex) {
            fault();
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
