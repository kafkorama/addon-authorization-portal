package com.migratorydata.authorization;

import com.migratorydata.authorization.common.config.Configuration;
import com.migratorydata.authorization.hub.HubAuthorizationHandler;
import com.migratorydata.authorization.hub.PushConsumerListener;
import com.migratorydata.authorization.hub.common.CommonUtils;
import com.migratorydata.authorization.hub.common.Consumer;
import com.migratorydata.authorization.hub.common.Producer;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;
import com.migratorydata.extensions.authorization.v2.client.*;

public class ExtensionLoader implements MigratoryDataAuthorizationListener {

    private final MigratoryDataAuthorizationListener authorizationListener;

    private Consumer consumer;
    private Producer producer;

    public ExtensionLoader() {
        int numberOfClusterMembers = System.getProperty("com.migratorydata.extensions.authorization.clusterMembers", "1").split(",").length;

        Configuration conf = Configuration.getConfiguration();

        String jws = CommonUtils.generateToken(conf.getApiSegment(),
                CommonUtils.createAllPermissions("/" + conf.getAdminUserSegment() + "/" + conf.getApiSegment() + "/*"),
                conf.getSecretKey());

        producer = new Producer(conf.getClusterInternalServers(), jws);

        authorizationListener = new HubAuthorizationHandler(producer, conf.getSubjectStats(), conf.getClusterServerId(),
                conf.getMillisBeforeRenewal(), conf.getJwtVerifyParser(), conf.getUrlRevokedTokens(), conf.getUrlApiLimits(),
                numberOfClusterMembers);

        consumer = new Consumer(conf.getClusterInternalServers(), jws, conf.getSubjectStats(), new PushConsumerListener((HubAuthorizationHandler) authorizationListener));
        consumer.begin();
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
        if (consumer != null) {
            consumer.end();
        }
    }
}
