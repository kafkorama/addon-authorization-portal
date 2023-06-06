package com.migratorydata.authorization.hub.common;

public class Metric {

    public final String appid;
    public final int connections;
    public final int messages;
    public final int subjects;

    public Metric(String appid, int connections, int messages, int subjects) {
        this.appid = appid;
        this.connections = connections;
        this.messages = messages;
        this.subjects = subjects;
    }
}
