package com.migratorydata.authorization.helper;

import com.migratorydata.extensions.authorization.v2.client.Client;
import com.migratorydata.extensions.authorization.v2.client.EventUpdateToken;

public class EventUpdate implements EventUpdateToken {

    private Client client;

    public EventUpdate(Client client) {
        this.client = client;
    }

    @Override
    public Client getClient() {
        return client;
    }
}
