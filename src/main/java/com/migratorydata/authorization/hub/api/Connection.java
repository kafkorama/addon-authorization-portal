package com.migratorydata.authorization.hub.api;

public class Connection {

    private int connections = 0;
    private long lastUpdate = System.currentTimeMillis();

    public void setConnections(Integer nrConnections) {
        this.connections = nrConnections;
        lastUpdate = System.currentTimeMillis();
    }

    public long getLastUpdate() {
        return lastUpdate;
    }

    public int getConnections() {
        return connections;
    }
}
