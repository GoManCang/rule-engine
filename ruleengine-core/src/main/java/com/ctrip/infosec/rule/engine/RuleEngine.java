/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ctrip.infosec.rule.engine;

import com.ctrip.infosec.common.model.RiskFact;
import java.io.ByteArrayInputStream;
import java.util.*;
import org.drools.KnowledgeBase;
import org.drools.builder.KnowledgeBuilder;
import org.drools.builder.KnowledgeBuilderErrors;
import org.drools.builder.KnowledgeBuilderFactory;
import org.drools.builder.ResourceType;
import org.drools.definition.KnowledgePackage;
import org.drools.io.ResourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author zhengbaiyun
 */
public abstract class RuleEngine {

    private static final Logger logger = LoggerFactory.getLogger(RuleEngine.class);
    /**
     * KnowledgeBase
     */
    protected KnowledgeBase kbase;

    /**
     * 初始化引擎
     */
    public abstract void initEngine();

    /**
     * 规则更新, 返回错误信息List
     */
    public abstract List<String> updateRules();

    protected void addKnowledgePackages(Collection<KnowledgePackage> kpackages) {
        this.kbase.addKnowledgePackages(kpackages);
    }

    protected void removeKnowledgePackages(Collection<KnowledgePackage> kpackages) {
        for (KnowledgePackage pkg : kpackages) {
            this.kbase.removeKnowledgePackage(pkg.getName());
        }
    }

    protected Collection<KnowledgePackage> getKnowledgePackagesFromString(String ruleContent) {
        KnowledgeBuilder kbuilder = KnowledgeBuilderFactory.newKnowledgeBuilder();
        ByteArrayInputStream stream = new ByteArrayInputStream(ruleContent.getBytes());
        kbuilder.add(ResourceFactory.newInputStreamResource(stream), ResourceType.DRL);
        if (kbuilder.hasErrors()) {
            logger.error("compile error:");
            KnowledgeBuilderErrors kbuidlerErrors = kbuilder.getErrors();
            for (Iterator iter = kbuidlerErrors.iterator(); iter.hasNext();) {
                logger.error(iter.next().toString());
            }
            return new ArrayList<KnowledgePackage>();
        }
        Collection<KnowledgePackage> kpackages = kbuilder.getKnowledgePackages();
        return kpackages;
    }
}
