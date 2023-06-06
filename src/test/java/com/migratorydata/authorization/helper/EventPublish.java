package com.migratorydata.authorization.helper;

import com.migratorydata.extensions.authorization.v2.client.Client;

public class EventPublish implements com.migratorydata.extensions.authorization.v2.client.EventPublish {

    private String subject;
    private Client client;

    private boolean permission = false;

    public EventPublish(Client client, String subject) {
        this.subject = subject;
        this.client = client;
    }

    @Override
    public Client getClient() {
        return client;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public void authorize(boolean permission) {
        this.permission = permission;
    }

    public boolean getPermission() {
        return permission;
    }
}
