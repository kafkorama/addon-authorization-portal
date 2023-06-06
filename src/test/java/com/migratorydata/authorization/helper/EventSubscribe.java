package com.migratorydata.authorization.helper;

import com.migratorydata.extensions.authorization.v2.client.Client;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EventSubscribe implements com.migratorydata.extensions.authorization.v2.client.EventSubscribe {

    private Client client;
    private List<String> subjects;

    private Map<String, Boolean> permissions = new HashMap<>();

    public EventSubscribe(Client client, List<String> subjects) {
        this.client = client;
        this.subjects = subjects;
    }

    @Override
    public Client getClient() {
        return client;
    }

    @Override
    public List<String> getSubjects() {
        return subjects;
    }

    @Override
    public void authorize(Map<String, Boolean> permissions) {
        this.permissions = permissions;
    }

    public Map<String, Boolean> getPermissions() {
        return permissions;
    }
}
