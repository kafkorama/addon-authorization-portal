package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.common.config.Configuration;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;

public class EventBase {

    protected MigratoryDataAuthorizationListener authorizationListener;

    protected void initialize() {
        Configuration conf = Configuration.getConfiguration();

        authorizationListener = new HubAuthorizationHandler(conf.getMillisBeforeRenewal(), conf.getJwtVerifyParser(), conf.getUrlRevokedTokens(), conf.getUrlJwtSecrets());
    }

}
