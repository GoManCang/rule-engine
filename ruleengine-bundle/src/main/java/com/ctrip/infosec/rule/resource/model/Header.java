package com.ctrip.infosec.rule.resource.model;

import javax.xml.bind.annotation.XmlAttribute;

/**
 * Created by yxjiang on 2015/7/7.
 */
public class Header {
    @XmlAttribute
    private String ServerIP;
    @XmlAttribute
    private String ShouldRecordPerformanceTime;
    @XmlAttribute
    private String UserID;
    @XmlAttribute
    private String RequestID;
    @XmlAttribute
    private String ResultCode;
    @XmlAttribute
    private String AssemblyVersion;
    @XmlAttribute
    private String RequestBodySize;
    @XmlAttribute
    private String SerializeMode;
    @XmlAttribute
    private String RouteStep;
    @XmlAttribute
    private String Environment;

    public String getServerIP() {
        return ServerIP;
    }

    public void setServerIP(String serverIP) {
        ServerIP = serverIP;
    }

    public String getShouldRecordPerformanceTime() {
        return ShouldRecordPerformanceTime;
    }

    public void setShouldRecordPerformanceTime(String shouldRecordPerformanceTime) {
        ShouldRecordPerformanceTime = shouldRecordPerformanceTime;
    }

    public String getUserID() {
        return UserID;
    }

    public void setUserID(String userID) {
        UserID = userID;
    }

    public String getRequestID() {
        return RequestID;
    }

    public void setRequestID(String requestID) {
        RequestID = requestID;
    }

    public String getResultCode() {
        return ResultCode;
    }

    public void setResultCode(String resultCode) {
        ResultCode = resultCode;
    }

    public String getAssemblyVersion() {
        return AssemblyVersion;
    }

    public void setAssemblyVersion(String assemblyVersion) {
        AssemblyVersion = assemblyVersion;
    }

    public String getRequestBodySize() {
        return RequestBodySize;
    }

    public void setRequestBodySize(String requestBodySize) {
        RequestBodySize = requestBodySize;
    }

    public String getSerializeMode() {
        return SerializeMode;
    }

    public void setSerializeMode(String serializeMode) {
        SerializeMode = serializeMode;
    }

    public String getRouteStep() {
        return RouteStep;
    }

    public void setRouteStep(String routeStep) {
        RouteStep = routeStep;
    }

    public String getEnvironment() {
        return Environment;
    }

    public void setEnvironment(String environment) {
        Environment = environment;
    }
}
