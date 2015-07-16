package com.ctrip.infosec.rule.executor;

import com.ctrip.infosec.common.Constants;
import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.event.DataUnitColumnType;
import com.ctrip.infosec.configs.event.DatabaseType;
import com.ctrip.infosec.configs.event.DistributionChannel;
import com.ctrip.infosec.configs.event.enums.PersistColumnSourceType;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.convert.RiskFactConvertRuleService;
import com.ctrip.infosec.rule.convert.RiskFactPersistStrategy;
import com.ctrip.infosec.rule.convert.internal.InternalRiskFact;
import com.ctrip.infosec.rule.convert.persist.*;
import com.ctrip.infosec.rule.resource.RiskLevelData;
import com.ctrip.infosec.rule.resource.model.SaveRiskLevelDataRequest;
import com.ctrip.infosec.rule.resource.model.SaveRiskLevelDataResponse;
import com.google.common.collect.Lists;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.ctrip.infosec.common.SarsMonitorWrapper.afterInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.beforeInvoke;
import static com.ctrip.infosec.common.SarsMonitorWrapper.fault;

/**
 * Created by yxjiang on 2015/7/16.
 */
@Service
public class Offline4jService {
    private static final Logger logger = LoggerFactory.getLogger(Offline4jService.class);
    @Autowired
    private PersistPreRuleExecutorService persistPreRuleExecutorService;
    @Autowired
    private RiskFactConvertRuleService riskFactConvertRuleService;

    public InternalRiskFact saveForOffline(RiskFact fact) {
        long reqId;// 执行落地前规则
        persistPreRuleExecutorService.executePostRules(fact, false);
        //riskfact 数据映射转换
        InternalRiskFact internalRiskFact = riskFactConvertRuleService.apply(fact);
        if (internalRiskFact != null) {
            // 数据落地
            if (RiskFactPersistStrategy.supportLocally(internalRiskFact)) {
                localSave(fact, internalRiskFact);
            } else {
                //调用外部存储服务

            }
        }
        return internalRiskFact;
    }

    private void localSave(RiskFact fact, InternalRiskFact internalRiskFact) {
        long reqId;
        String operation = internalRiskFact.getEventPoint() + ".persist-info";
        try {
            beforeInvoke(operation);
            Integer riskLevel = MapUtils.getInteger(fact.finalResult, Constants.riskLevel, 0);
            String resultRemark = "NEW: " + resultToString(fact.results);
            RiskFactPersistManager persistManager = RiskFactPersistStrategy.preparePersistence(internalRiskFact);
            PersistContext persistContext = persistManager.persist(riskLevel, resultRemark);
            reqId = persistManager.getGeneratedReqId();
            internalRiskFact.setReqId(reqId);
            // 调用远程服务落地，
            if (MapUtils.getBoolean(fact.ext, "offline4j-push-ebank", false)) {
                SaveRiskLevelDataRequest request = new SaveRiskLevelDataRequest();
                request.setResID(reqId);
                request.setReqID(reqId);
                request.setOrderID(persistManager.getLong("InfoSecurity_RiskLevelData.OrderID"));
                request.setRiskLevel(riskLevel);
                request.setRemark(persistManager.getString("InfoSecurity_RiskLevelData.Remark"));
                request.setOrderType(persistManager.getInteger("InfoSecurity_RiskLevelData.OrderID"));
                request.setOriginalRiskLevel(riskLevel);
                Map<String, Object> ebankData = MapUtils.getMap(fact.ext, "ebank-data");
                request.setInfoID(MapUtils.getInteger(ebankData, "infoId", 0));
                request.setIsForigenCard(MapUtils.getString(ebankData, "isForeignCard", ""));
                request.setCardInfoID(MapUtils.getInteger(ebankData, "cardInfoID", 0));

                SaveRiskLevelDataResponse ebankResp = RiskLevelData.save(request);
                if (ebankResp != null) {
                    // 调用ebank成功，修改InfoSecurity_RiskLevelData.TransFlag
                    updateTransFlag(reqId, persistContext);
                }
            } else {
                // 无需调用ebank，直接修改InfoSecurity_RiskLevelData.TransFlag
                updateTransFlag(reqId, persistContext);
            }
        } catch (Exception ex) {
            fault(operation);
            logger.error(Contexts.getLogPrefix() + "fail to persist risk fact.", ex);
        } finally {
            afterInvoke(operation);
        }
    }

    private void updateTransFlag(long reqId, PersistContext persistContext) throws DbExecuteException {
        // 更新InfoSecurity_RiskLevelData的TransFlag = 32
        RdbmsUpdate update = new RdbmsUpdate();
        DistributionChannel channel = new DistributionChannel();
        String allInOneDb = RiskFactPersistStrategy.allInOne4ReqId;
        channel.setChannelNo(allInOneDb);
        channel.setDatabaseType(DatabaseType.AllInOne_SqlServer);
        channel.setChannelDesc(allInOneDb);
        channel.setDatabaseURL(allInOneDb);
        update.setChannel(channel);
        update.setTable("InfoSecurity_RiskLevelData");

        Map<String, PersistColumnProperties> map = new HashMap<>();
        PersistColumnProperties pcp = new PersistColumnProperties();
        pcp.setValue(reqId);
        pcp.setColumnType(DataUnitColumnType.Long);
        pcp.setPersistColumnSourceType(PersistColumnSourceType.DB_PK);
        map.put("ReqID", pcp);

        pcp = new PersistColumnProperties();
        pcp.setValue(32);
        pcp.setPersistColumnSourceType(PersistColumnSourceType.DATA_UNIT);
        pcp.setColumnType(DataUnitColumnType.Int);
        map.put("TransFlag", pcp);

        update.setColumnPropertiesMap(map);

        update.execute(persistContext);
    }

    private String resultToString(Map<String, Map<String, Object>> results) {
        List<String> result = Lists.newArrayList();
        if (MapUtils.isNotEmpty(results)) {
            for (Map.Entry<String, Map<String, Object>> entry : results.entrySet()) {
                try {
                    Map<String, Object> val = entry.getValue();
                    if (val != null) {
                        Object level = val.get("riskLevel");
                        if (level != null) {
                            int riskLevel = Integer.valueOf(level.toString());
                            if (riskLevel > 0) {
                                result.add(entry.getKey());
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.error(Contexts.getLogPrefix() + "get risk level from results failed.", e);
                }
            }
        }
        return StringUtils.join(result, ',');
    }
}
