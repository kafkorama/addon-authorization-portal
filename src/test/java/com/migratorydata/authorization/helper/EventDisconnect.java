package com.migratorydata.authorization.helper;

import com.migratorydata.extensions.authorization.v2.client.Client;

public class EventDisconnect implements com.migratorydata.extensions.authorization.v2.client.EventDisconnect {

    private Client client;

    public EventDisconnect(Client client) {
        this.client = client;
    }

    @Override
    public Client getClient() {
        return client;
    }

}
