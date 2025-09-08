package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.AuthorizationHandler;
import com.migratorydata.authorization.config.Configuration;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;

public class EventBase {

    protected MigratoryDataAuthorizationListener authorizationListener;

    protected void initialize() {
        Configuration conf = Configuration.getConfiguration();

        authorizationListener = new AuthorizationHandler(conf.getMillisBeforeRenewal(), conf.getJwtParser(), conf.getPortalRevokedTokensUrl(), conf.getPortalSigningKeysUrl());
    }

}
