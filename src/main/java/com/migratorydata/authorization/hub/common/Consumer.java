package com.migratorydata.authorization.hub.common;

import com.migratorydata.client.MigratoryDataClient;
import com.migratorydata.client.MigratoryDataListener;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class Consumer {

    private final AtomicBoolean closed = new AtomicBoolean(false);

    private MigratoryDataClient client;

    private final List<String> topicList;

    public Consumer(String servers, String token, String topicStats, MigratoryDataListener listener) {
        client = new MigratoryDataClient();
        client.setServers(servers.split(","));
        client.setEntitlementToken(token);
        client.setReconnectPolicy(MigratoryDataClient.CONSTANT_WINDOW_BACKOFF);
        client.setReconnectTimeInterval(5);
        client.setListener(listener);

        topicList = Arrays.asList(topicStats);

        client.subscribe(topicList);
    }

    public void begin() {
        client.connect();
    }

    public void end() {
        client.disconnect();
        closed.set(true);
    }

}
