package com.migratorydata.authorization.helper;

import com.migratorydata.extensions.authorization.v2.client.Client;

public class EventConnect implements com.migratorydata.extensions.authorization.v2.client.EventConnect {

    private Client client;
    private String reason;
    private boolean permission = false;

    public EventConnect(Client client) {
        this.client = client;
    }

    @Override
    public Client getClient() {
        return client;
    }

    @Override
    public void authorize(boolean permission, String reason) {
        this.permission = permission;
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }

    public boolean getPermission() {
        return permission;
    }
}
