package com.migratorydata.authorization.hub.common;

import com.migratorydata.client.MigratoryDataClient;
import com.migratorydata.client.MigratoryDataListener;
import com.migratorydata.client.MigratoryDataMessage;

public class Producer implements MigratoryDataListener {

    private final MigratoryDataClient client;
    private int id;

    public Producer(String servers, String token) {
        client = new MigratoryDataClient();
        client.setServers(servers.split(","));
        client.setEntitlementToken(token);
        client.setReconnectPolicy(MigratoryDataClient.CONSTANT_WINDOW_BACKOFF);
        client.setReconnectTimeInterval(5);
        client.setListener(this);

        client.connect();
    }

    public void write(String topic, byte[] data) {
        MigratoryDataMessage msg = new MigratoryDataMessage(topic, data, "closure-" + id++, MigratoryDataMessage.QoS.STANDARD, false);
        client.publish(msg);
    }

    @Override
    public void onMessage(MigratoryDataMessage migratoryDataMessage) {

    }

    @Override
    public void onStatus(String status, String info) {
        System.out.printf("Extension-Producer-%s-%s%n", status, info);
    }
}
