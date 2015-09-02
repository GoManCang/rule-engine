/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.venus;

import com.ctrip.infosec.common.model.RiskFact;
import com.meidusa.venus.annotations.Endpoint;
import com.meidusa.venus.annotations.Param;
import com.meidusa.venus.annotations.Service;

/**
 * 规则引擎同步验证接口
 *
 * @author zhengby
 */
@Service(name = "RuleEngineRemoteService")
public interface RuleEngineRemoteService {

    @Endpoint
    @Deprecated
    public RiskFact verify(@Param(name = "fact") RiskFact fact);

    @Endpoint
    public String execute(@Param(name = "fact") String factTxt);

}
