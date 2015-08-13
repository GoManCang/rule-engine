package com.ctrip.infosec.rule.executor;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.ctrip.infosec.common.model.RiskFact;
import com.ctrip.infosec.configs.Configs;
import com.ctrip.infosec.configs.event.CounterPushRule;
import com.ctrip.infosec.configs.utils.EventBodyUtils;
import com.ctrip.infosec.rule.Contexts;
import com.ctrip.infosec.rule.resource.Counter;
import com.ctrip.infosec.rule.utils.UnionUtil;
import com.ctrip.infosec.rule.utils.UnionUtil.INode;
import com.ctrip.infosec.rule.utils.UnionUtil.INodeDataHandle;
import com.ctrip.infosec.rule.utils.UnionUtil.UnionNode;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 *
 * @author sjchi
 * @date 2015年5月6日 下午3:16:01
 */
@Service
public class CounterPushRulesExecutorService {

    private static final Logger logger = LoggerFactory.getLogger(CounterPushRulesExecutorService.class);

    public RiskFact executeCounterPushRules(RiskFact fact, boolean isAsync) {
        execute(fact, isAsync);
        return fact;
    }

    private void execute(RiskFact fact, boolean isAsync) {

        // matchRules      
        List<CounterPushRule> matchedRules = Configs.matchCounterPushRules(fact);
        logger.info(Contexts.getLogPrefix() + "matched CounterPushRules: " + matchedRules.size());

        StopWatch clock = new StopWatch();
        try {
            clock.reset();
            clock.start();

            for (CounterPushRule rule : matchedRules) {
                executeInternal(fact, rule);
            }

            clock.stop();
            long handlingTime = clock.getTime();
            if (handlingTime > 50) {
//                logger.info(Contexts.getLogPrefix() + "CounterPushRuleExecutorService#execute: eventPoint: " + fact.getEventPoint() + ", usage: " + handlingTime + "ms");
            }

        } catch (Throwable ex) {
            logger.warn(Contexts.getLogPrefix() + "invoke CounterPushRuleExecutorService#execute failed. eventpoint: " + fact.getEventPoint(), ex);
        }

    }

    /**
     * 根据规则来组装需要推送的dataMap,然后执行Counter#push
     *
     * @param rule
     * @param fact
     */
    private void executeInternal(RiskFact fact, CounterPushRule rule) {

        List<Map<String, String>> dataMaps = analysePushDatas(fact, rule);

        for (Map<String, String> dataMap : dataMaps) {

            if (dataMap.size() > 0) {

                Counter.push(rule.getBizNo(), dataMap);

//    			logger.info(Contexts.getLogPrefix() + "Counter push: bizNo-->" + rule.getBizNo() + ",eventPoint-->" + rule.getEventPoint() + ",dataMap-->" + JSON.toJSONString(dataMap));
            } else {
                logger.warn(Contexts.getLogPrefix() + "Counter push: bizNo-->" + rule.getBizNo() + ",eventPoint-->" + rule.getEventPoint() + ",dataMap is empty");
            }
        }
    }

    /**
     * @return List<Map> 每个map代表需要push的数据，list.size()代表需要push的次数。<br/>
     * 因为Counter push存在数组取值，所以涉及到数组的地方都会进行循环推送<br1/>
     * 如果Counter push字段中存在多个数组，那么需要进行类笛卡儿积组合，然后进行循环推送
     *
     */
    private List<Map<String, String>> analysePushDatas(RiskFact fact, CounterPushRule rule) {

        List<Map<String, String>> result = Lists.newArrayList();

        //直接推送的数据
        final Map<String, String> basicMap = Maps.newHashMap();
        //数组数据（即需要循环推送的数据）
        final Map<String, LoopItem> loopItems = Maps.newHashMap();

        //分析出basicItem和loopItems
        Map<String, String> fieldMap = rule.getFieldMap();
        for (Entry<String, String> entry : fieldMap.entrySet()) {

            String key = entry.getValue();
            String[] keyTree = key.split("\\.");

            Object rootValue = fact.getEventBody().get(keyTree[0]);
            if (null == rootValue) {
                continue;
            }

            if (keyTree.length > 1 && (rootValue instanceof List || rootValue.getClass().isArray())) {
                //第一层是数组或者列表，则纳入loopItem中
                LoopItem loopItem = loopItems.get(keyTree[0]);
                if (null == loopItem) {
                    loopItem = new LoopItem(rootValue, keyTree[0]);
                    loopItems.put(keyTree[0], loopItem);
                }

                //增加需要从loopItem每个itemMap中需要获取的数据的key和aliasKey(别名)
                loopItem.addDataKey(entry.getKey(), key.substring(key.indexOf(".") + 1));

            } else {
                //表示可以直接获取的元素,支持多层取值
                String data = EventBodyUtils.valueAsString(fact.getEventBody(), entry.getValue());
                if (!StringUtils.isEmpty(data)) {
                    basicMap.put(entry.getKey(), data);
                }
            }
        }

        if (null != loopItems && loopItems.size() > 0) {

            //进行类笛卡儿积操作
            Iterator<LoopItem> iterator = loopItems.values().iterator();
            List<INode<DataWrapper>> g1 = iterator.next().create();
            while (iterator.hasNext()) {
                g1 = UnionUtil.union(g1, iterator.next().create());
            }

            //循环获取push所需map
            for (INode<DataWrapper> unionNode : g1) {

                final Map pushData = new HashMap();
                unionNode.searchData(new INodeDataHandle<DataWrapper>() {

                    @Override
                    public void handle(DataWrapper data) {
                        pushData.putAll(data.getData());
                    }
                });
                //将基础数据放入pushData
                pushData.putAll(basicMap);

                result.add(pushData);
            }

        } else {
            result.add(basicMap);
        }

        return result;
    }

    private class LoopItem {

        private String loopKey;
        private List dataItems;//循环数据,每项代表一个map数据源
        private Map<String, String> aliasDataKeyMap = Maps.newHashMap();

        /**
         * @param _dataItems 数据源
         * @param loopKey loop的关键编号,让类似 loopKey.a,loopKey.b的元素归入同一个loopItem中
         */
        public LoopItem(Object _dataItems, String loopKey) {

            if (_dataItems instanceof List) {
                dataItems = (List) _dataItems;
            } else {
                //一定是数组
                dataItems = Lists.newArrayList((Object[]) _dataItems);
            }

            this.loopKey = loopKey;
        }

        public List<INode<DataWrapper>> create() {

            List<INode<DataWrapper>> result = Lists.newArrayList();

            for (Object _item : dataItems) {

                DataWrapper map = new DataWrapper((Map) _item, aliasDataKeyMap);
                result.add(new UnionNode<DataWrapper>(map));
            }

            return result;
        }

        /**
         * @param aliaskey 用于push到counter server识别的key
         * @param dataKey 用于获取值得key
         */
        public void addDataKey(String aliaskey, String dataKey) {
            aliasDataKeyMap.put(aliaskey, dataKey);

        }

    }

    private class DataWrapper {

        private Map item;//数据源
        private Map<String, String> aliasDataKeyMap;//需要取值的aliasKey和值key,aliasKey用于输出时需要

        /**
         * @param _item 数据源map
         * @param aliasDataKeyMap 需要的key和别名集合
         */
        public DataWrapper(Map _item, Map<String, String> aliasDataKeyMap) {
            this.item = _item;
            this.aliasDataKeyMap = aliasDataKeyMap;
        }

        /**
         * 从数据源获取真正需要的数据
         */
        public Map getData() {

            Map result = Maps.newHashMap();

            for (Entry entry : aliasDataKeyMap.entrySet()) {

                String data = EventBodyUtils.valueAsString(item, ObjectUtils.toString(entry.getValue()));
                if (!StringUtils.isEmpty(data)) {
                    result.put(entry.getKey(), data);
                }
            }

            return result;
        }

    }

//    public static void main(String[] args) {
//
//        CounterPushRulesExecutorService service = new CounterPushRulesExecutorService();
//
//        RiskFact fact = new RiskFact();
//        fact.getEventBody().put("hello", "world");
//        List list = Lists.newArrayList(ImmutableMap.of("hello1", "world1"), ImmutableMap.of("hello1", "world2"));
//        fact.getEventBody().put("hellos", list);
//        List list2 = Lists.newArrayList(ImmutableMap.of("hello2", "world1"), ImmutableMap.of("hello2", "world2"));
//        fact.getEventBody().put("hello2s", list2);
//
//        CounterPushRule rule = new CounterPushRule();
//        rule.getFieldMap().put("h", "hello");
//        rule.getFieldMap().put("h1", "hellos.hello1");
//        rule.getFieldMap().put("h2", "hello2s.hello2");
//
//        List<Map<String, String>> result = service.analysePushDatas(fact, rule);
//        System.out.println(result);
//    }

}
