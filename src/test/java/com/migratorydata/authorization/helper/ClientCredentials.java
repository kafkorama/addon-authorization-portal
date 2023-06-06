package com.migratorydata.authorization.helper;

import com.migratorydata.extensions.authorization.v2.client.Client;
import com.migratorydata.extensions.authorization.v2.client.StatusNotification;

import java.util.Map;

public class ClientCredentials implements Client {

    private String token;
    private String clientAddress;
    private StatusNotification statusNotification;
    private boolean disconnect;

    public ClientCredentials(String token, String clientAddress) {
        this.token = token;
        this.clientAddress = clientAddress;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public String getClientAddress() {
        return clientAddress;
    }

    @Override
    public Map<String, Object> getAdditionalInfo() {
        return null;
    }

    @Override
    public void disconnect() {
        disconnect = true;
    }

    public boolean isDisconnect() {
        return disconnect;
    }

    @Override
    public void sendStatusNotification(StatusNotification response) {
        this.statusNotification = response;
    }

    public StatusNotification getNotification() {
        return statusNotification;
    }
}
