package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.common.config.Configuration;
import com.migratorydata.authorization.hub.common.CommonUtils;
import com.migratorydata.authorization.hub.common.Producer;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;

public class EventBase {

    protected MigratoryDataAuthorizationListener authorizationListener;

    protected void initialize() {
        int numberOfClusterMembers = System.getProperty("com.migratorydata.extensions.authorization.clusterMembers", "1").split(",").length;

        Configuration conf = Configuration.getConfiguration();

        String jws = CommonUtils.generateToken(conf.getApiSegment(),
                CommonUtils.createAllPermissions("/" + conf.getAdminUserSegment() + "/" + conf.getApiSegment() + "/*"),
                conf.getSecretKey());

        Producer producer = new Producer(conf.getClusterInternalServers(), jws);

        authorizationListener = new HubAuthorizationHandler(producer, conf.getSubjectStats(), conf.getClusterServerId(),
                conf.getMillisBeforeRenewal(), conf.getJwtVerifyParser(), conf.getUrlRevokedTokens(), conf.getUrlApiLimits(), numberOfClusterMembers);
    }

}
