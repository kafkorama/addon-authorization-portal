package com.migratorydata.authorization;

import com.migratorydata.authorization.config.Configuration;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;
import com.migratorydata.extensions.authorization.v2.client.*;

public class ExtensionLoader implements MigratoryDataAuthorizationListener {

    private final MigratoryDataAuthorizationListener authorizationListener;

    public ExtensionLoader() {
        Configuration conf = Configuration.getConfiguration();
        authorizationListener = new AuthorizationHandler(conf.getMillisBeforeRenewal(), conf.getJwtParser(), conf.getPortalRevokedTokensUrl(), conf.getPortalSigningKeysUrl());
    }

    @Override
    public void onClientConnect(EventConnect eventConnect) {
        authorizationListener.onClientConnect(eventConnect);
    }

    @Override
    public void onClientUpdateToken(EventUpdateToken eventUpdateToken) {
        authorizationListener.onClientUpdateToken(eventUpdateToken);
    }

    @Override
    public void onClientSubscribe(EventSubscribe eventSubscribe) {
        authorizationListener.onClientSubscribe(eventSubscribe);
    }

    @Override
    public void onClientPublish(EventPublish eventPublish) {
        authorizationListener.onClientPublish(eventPublish);
    }

    @Override
    public void onClientDisconnect(EventDisconnect eventDisconnect) {
        authorizationListener.onClientDisconnect(eventDisconnect);
    }

    @Override
    public void onInit() {
        authorizationListener.onInit();
    }

    @Override
    public void onDispose() {
        authorizationListener.onDispose();
    }
}
