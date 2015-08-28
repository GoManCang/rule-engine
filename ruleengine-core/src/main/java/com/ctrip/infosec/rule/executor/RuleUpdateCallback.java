/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.configs.ConfigsLoadedCallback;
import com.ctrip.infosec.rule.engine.*;
import org.springframework.beans.factory.annotation.Autowired;

/**
 *
 * @author zhengby
 */
public class RuleUpdateCallback implements ConfigsLoadedCallback {

    @Autowired
    private StatelessRuleEngine statelessRuleEngine;
    @Autowired
    private StatelessPreRuleEngine statelessPreRuleEngine;
    @Autowired
    private StatelessPostRuleEngine statelessPostRuleEngine;
    @Autowired
    private StatelessPersistPreRuleEngine statelessPersistPreRuleEngine;
    @Autowired
    private StatelessPersistPostRuleEngine statelessPersistPostRuleEngine;
    @Autowired
    private StatelessWhitelistRuleEngine statelessWhitelistRuleEngine;

    @Override
    public void onConfigsLoaded() {
        statelessRuleEngine.updateRules();
        statelessPreRuleEngine.updateRules();
        statelessPostRuleEngine.updateRules();
        statelessPersistPreRuleEngine.updateRules();
        statelessPersistPostRuleEngine.updateRules();
        statelessWhitelistRuleEngine.updateRules();
    }

}
