package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.hub.common.Metric;
import com.migratorydata.client.MigratoryDataListener;
import com.migratorydata.client.MigratoryDataMessage;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class PushConsumerListener implements MigratoryDataListener {

    private final HubAuthorizationHandler authorizationListener;

    public PushConsumerListener(HubAuthorizationHandler authorizationListener) {
        this.authorizationListener = authorizationListener;
    }

    @Override
    public void onMessage(MigratoryDataMessage m) {
        //logger.info("Extension-Consumer-" + m);

        if (m.getMessageType() == MigratoryDataMessage.MessageType.SNAPSHOT) {
            return;
        }

        JSONObject result = new JSONObject(new String(m.getContent()));

        String update = result.getString("up");
        String serverName = result.getString("server");
        JSONArray metrics = result.getJSONArray("metrics");
        Map<String, Metric> metricsMap = new HashMap<>();
        for (int i = 0; i < metrics.length(); i++) {
            String appid = metrics.getJSONObject(i).getString("appid");
            int connections = metrics.getJSONObject(i).getInt("con");
            int messages = metrics.getJSONObject(i).getInt("msg");
            int subjects = metrics.getJSONObject(i).getInt("sbj");
            metricsMap.put(appid, new Metric(appid, connections, messages,subjects));
        }

        authorizationListener.updateMetrics(metricsMap, serverName, update);
    }

    @Override
    public void onStatus(String status, String info) {
        System.out.println("Extension-Consumer-" + status + " " + info);
    }

}
