package com.migratorydata.authorization.hub.limits;

import com.migratorydata.authorization.hub.common.Producer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.migratorydata.authorization.common.config.Util.toEpochNanos;

public class LimitsAgregationHandler {

    private final Producer producer;
    private final String serverName;
    private final String topicStats;

    private final int numberOfClusterMembers;

    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private Map<String, MetricsPerApi> apis = new HashMap<>();

    public LimitsAgregationHandler(Producer producer, String serverName, String topicStats, int numberOfClusterMembers) {
        this.producer = producer;

        this.serverName = serverName;
        this.topicStats = topicStats;

        this.executor.scheduleAtFixedRate(() -> {
            try {
                update();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }, 0, 5, TimeUnit.SECONDS);

        this.numberOfClusterMembers = numberOfClusterMembers;
    }


    public void onConnect(String appId) {
        executor.execute(() -> {
            MetricsPerApi metric = apis.get(appId);
            if (metric == null) {
                metric = new MetricsPerApi();
                apis.put(appId, metric);
            }
            metric.incConnections();
        });
    }

    public void onDisconnect(String appId) {
        executor.execute(() -> {
            MetricsPerApi metric = apis.get(appId);
            if (metric != null && metric.getConnections() > 0) {
                metric.decConnections();
            }
        });
    }


    public void onSubscribe(String appId, List<String> subject) {
        executor.execute(() -> {
            MetricsPerApi metricsPerApi = apis.get(appId);
            if (metricsPerApi == null) {
                metricsPerApi = new MetricsPerApi();
                apis.put(appId, metricsPerApi);
            }

            metricsPerApi.inc(subject);
        });
    }

    public void onUnsubscribe(String appId, Collection<String> subjects) {
        executor.execute(() -> {
            MetricsPerApi metricsPerApi = apis.get(appId);
            if (metricsPerApi != null) {
                metricsPerApi.dec(subjects);
            }
        });
    }

    public void onPublish(String appId, String subject) {
        executor.execute(() -> {
            MetricsPerApi metricsPerApi = apis.get(appId);
            if (metricsPerApi != null) {
                metricsPerApi.countMessages(subject, numberOfClusterMembers);
            }
        });
    }

    // TODO: possible optimizations
    // send data compressed
    // send smaller messages when there are many apis (100 apis per message?)
    // don't send apis with 0 messages.
    private void update() {
        JSONObject connectionsStats = new JSONObject();
        connectionsStats.put("up", "con_msg");
        connectionsStats.put("server", serverName);
        connectionsStats.put("timestamp", toEpochNanos(Instant.now()));

        JSONArray metrics = new JSONArray();
        for (Map.Entry<String, MetricsPerApi> entry : apis.entrySet()) {
            JSONObject metric = new JSONObject();
            metric.put("appid", entry.getKey());
            metric.put("con", entry.getValue().getConnections());
            metric.put("msg", entry.getValue().getAndReset());
            metric.put("sbj", 0);
            metrics.put(metric);
        }
        connectionsStats.put("metrics", metrics);

        producer.write(topicStats, connectionsStats.toString().getBytes());
    }
}
