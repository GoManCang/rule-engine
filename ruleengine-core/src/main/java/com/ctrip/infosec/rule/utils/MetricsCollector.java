package com.ctrip.infosec.rule.utils;

import com.ctrip.framework.clogging.agent.aggregator.impl.Aggregator;
import com.ctrip.framework.clogging.agent.aggregator.impl.Metrics;

/**
 * Created by jizhao on 2015/7/28.
 */
public class MetricsCollector {
    private static Aggregator aggregator = Aggregator.getMetricsAggregator(60);

    public static class MetricsBuilder {

        protected final Metrics metrics;
        private static String METRIC_NAME = "rule.engine.ws";

        public MetricsBuilder() {
            this.metrics = new Metrics(METRIC_NAME);
            this.metrics.setValue(1);

        }

        public MetricsBuilder elapsed(long elapsed){
            this.metrics.addTag("elapsed", String.valueOf(elapsed));
            return  this;
        }

        public void put() {
            aggregator.add(this.metrics);
        }
    }


}
