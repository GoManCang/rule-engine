package com.ctrip.infosec.rule.engine;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.Rule;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import java.util.*;
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

/**
 * Stateless引擎
 *
 * @author zhengbaiyun
 */
public class StatelessRuleEngine extends RuleEngine {

    private static final Logger logger = LoggerFactory.getLogger(StatelessRuleEngine.class);
    private StatelessKnowledgeSession statelessKSession;
    /**
     * Cache, Key为: packageName
     */
    Map<String, Rule> rulesInKBase = Maps.newHashMap();

    public void execute(String packageName, RiskFact fact) {
        if (!isRuleInKBase(packageName)) {
//            logger.warn("\"" + packageName + "\" is not exists, ignored.");
            return;
        }
        try {
            AgendaFilter filter = new PackageAgendaFilter(packageName);
            execStatelessRule(filter, fact);
        } catch (Exception ex) {
            logger.error("execute \"" + packageName + "\" exception.", ex);
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
    public List<String> updateRules() {
        logger.warn("exec updateRules() start.");

        List<String> errors = new ArrayList<String>();
        Map<String, Rule> newRulesInKBase = Maps.newHashMap();

        // 删除&更新Route规则
        for (Rule rule : Configs.getRules()) {
            String packageName = rule.getRuleNo();
            Rule ruleInBase = this.rulesInKBase.get(packageName);
            if (!rule.isEnabled()) {
                if (ruleInBase != null) {
                    try {
                        logger.warn("remove rule: " + packageName);
                        Collection<KnowledgePackage> kpackagesInBase = this.getKnowledgePackagesFromString(ruleInBase.getRuleContent());
                        this.removeKnowledgePackages(kpackagesInBase);
                        errors.add("remove rule[" + packageName + "] success.");
                    } catch (Exception ex) {
                        errors.add("remove rule[" + packageName + "] failed. message: " + ex.getMessage());
                        logger.error("remove rule failed.", ex);
                    }
                }
            } else {
                if (ruleInBase == null
                        || ruleInBase.getUpdatedAt().before(rule.getUpdatedAt())) {
                    try {
                        logger.warn("update rule: " + packageName);
                        Collection<KnowledgePackage> kpackages = this.getKnowledgePackagesFromString(rule.getRuleContent());
                        if (ruleInBase != null) {
                            // 修复规则更新可能失败的BUG, 更新前先remove掉
                            Collection<KnowledgePackage> kpackagesInBase = this.getKnowledgePackagesFromString(ruleInBase.getRuleContent());
                            this.removeKnowledgePackages(kpackagesInBase);
                        }
                        this.addKnowledgePackages(kpackages);
                        errors.add("update rule[" + packageName + "] success.");
                    } catch (Exception ex) {
                        errors.add("remove rule[" + packageName + "] failed. message: " + ex.getMessage());
                        logger.error("update rule failed.", ex);
                    }
                }

                newRulesInKBase.put(packageName, rule);
            }
        }
        logger.warn("exec updateRules() end.");

        // 最后更新缓存
        this.rulesInKBase = newRulesInKBase;
        return errors;
    }

    /**
     * 判断一个规则是否在KnowledgeBase中
     */
    public boolean isRuleInKBase(String packageName) {
        return rulesInKBase.containsKey(packageName);
    }

}
