package com.ctrip.infosec.rule.engine;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Caches;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.PersistPreRule;
import com.ctrip.infosec.configs.event.PostRule;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.drools.KnowledgeBaseConfiguration;
import org.drools.KnowledgeBaseFactory;
import org.drools.builder.KnowledgeBuilder;
import org.drools.builder.KnowledgeBuilderFactory;
import org.drools.command.Command;
import org.drools.command.CommandFactory;
import org.drools.command.runtime.rule.FireAllRulesCommand;
import org.drools.conf.EventProcessingOption;
import org.drools.definition.KnowledgePackage;
import org.drools.runtime.StatelessKnowledgeSession;
import org.drools.runtime.rule.AgendaFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * 落地前规则处理引擎
 *
 * @author yxjiang
 */
public class StatelessPersistPreRuleEngine extends RuleEngine {

    private static final Logger logger = LoggerFactory.getLogger(StatelessPersistPreRuleEngine.class);
    private StatelessKnowledgeSession statelessKSession;
    /**
     * Cache, Key为: packageName
     */
    Map<String, PersistPreRule> persistPreRulesInKBase = Maps.newHashMap();

    public void execute(String packageName, RiskFact fact) {
        if (isRuleInKBase(packageName)) {
            try {
                AgendaFilter filter = new PackageAgendaFilter(packageName);
                execStatelessRule(filter, fact);
            } catch (Exception ex) {
                logger.error("execute \"" + packageName + "\" exception.", ex);
            }
        }
    }

    public void execute(List<String> packageNames, RiskFact fact) {
        List<String> executablePackageNames = Lists.newArrayList();
        for (String packageName : packageNames) {
            if (isRuleInKBase(packageName)) {
                executablePackageNames.add(packageName);
            }
        }
        if (!executablePackageNames.isEmpty()) {
            try {
                AgendaFilter filter = new MultiPackageAgendaFilter(packageNames);
                execStatelessRule(filter, fact);
            } catch (Exception ex) {
                logger.error("execute \"" + packageNames + "\" exception.", ex);
            }
        }
    }

    protected void execStatelessRule(AgendaFilter filter, RiskFact fact) {
        ArrayList<Command> cmds = Lists.newArrayList();
        cmds.add(CommandFactory.newInsert(fact));
        cmds.add(CommandFactory.newSetGlobal("logger", logger));
        cmds.add(new FireAllRulesCommand(filter));
        statelessKSession.execute(CommandFactory.newBatchExecution(cmds));
    }

    /**
     * Init RuleEngine
     */
    protected void initKnowledgeBaseAndSession() {
        KnowledgeBuilder kbuilder = KnowledgeBuilderFactory.newKnowledgeBuilder();
        Collection<KnowledgePackage> kpackage = kbuilder.getKnowledgePackages();
        KnowledgeBaseConfiguration kbConf = KnowledgeBaseFactory.newKnowledgeBaseConfiguration();
        kbConf.setProperty("org.drools.sequential", "true");
        kbConf.setOption(EventProcessingOption.STREAM);
        kbase = KnowledgeBaseFactory.newKnowledgeBase(kbConf);
        kbase.addKnowledgePackages(kpackage);
        this.statelessKSession = kbase.newStatelessKnowledgeSession();
    }

    @Override
    public void initEngine() {
        logger.warn("exec initEngine() start.");
        initKnowledgeBaseAndSession();
        logger.warn("exec initEngine() end.");
    }

    /**
     * 规则更新
     */
    @Override
    public void updateRules() {
        logger.warn("exec updateRules() start.");
        Map<String, PersistPreRule> newPostRulesInKBase = Maps.newHashMap();

        // 删除&更新Route规则
        if (Caches.persistPreRuleConfigs != null) {
            for (PersistPreRule rule : Caches.persistPreRuleConfigs) {
                String packageName = rule.getEventPoint();
                PersistPreRule ruleInKBase = this.persistPreRulesInKBase.get(packageName);
                if (!rule.isEnabled()) {
                    if (ruleInKBase != null) {
                        try {
                            logger.warn("remove rule: " + packageName);
                            Collection<KnowledgePackage> kpackagesInBase = this.getKnowledgePackagesFromString(ruleInKBase.getRuleContent());
                            this.removeKnowledgePackages(kpackagesInBase);
                        } catch (Exception ex) {
                            logger.error("remove rule failed.", ex);
                        }
                    }
                } else {
                    if (ruleInKBase == null
                            || ruleInKBase.getUpdatedAt().before(rule.getUpdatedAt())) {
                        try {
                            logger.warn("update rule: " + packageName);
                            Collection<KnowledgePackage> kpackages = this.getKnowledgePackagesFromString(rule.getRuleContent());
                            this.addKnowledgePackages(kpackages);
                        } catch (Exception ex) {
                            logger.error("update rule failed.", ex);
                        }
                    }

                    newPostRulesInKBase.put(packageName, rule);
                }
            }
            logger.warn("exec updateRules() end.");

            // 最后更新缓存
            this.persistPreRulesInKBase = newPostRulesInKBase;
        }
    }

    /**
     * 判断一个规则是否在KnowledgeBase中
     */
    public boolean isRuleInKBase(String packageName) {
        return persistPreRulesInKBase.containsKey(packageName);
    }

}
