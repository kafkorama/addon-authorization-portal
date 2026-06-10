package com.migratorydata.authorization.hub;

import java.security.Key;
import java.util.HashMap;

import com.migratorydata.authorization.AuthorizationHandler;
import com.migratorydata.authorization.config.Configuration;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class EventBase {

    protected MigratoryDataAuthorizationListener authorizationListener;

    protected void initialize() {
        Configuration conf = Configuration.getConfiguration();

        Key jwtSigningKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode("He39zDQW7RdkOcxe3L9qvoSQ/ef40BG6Ro4hrHDjE+U="));
        JwtParser jwtParser = Jwts.parser().setSigningKey(jwtSigningKey).build();
        HashMap<String, JwtParser> jwtParsers = new HashMap<>();
        jwtParsers.put("testKeyId", jwtParser);

        authorizationListener = new AuthorizationHandler(conf.getMillisBeforeRenewal(), conf.getPortalRevokedTokensUrl(), conf.getPortalSigningKeysUrl(), conf.getPortalApiKey(), conf.getPortalRequestIntervalSeconds(), jwtParsers);
    }

}
