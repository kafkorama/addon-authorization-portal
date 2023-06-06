package com.migratorydata.authorization.common.token;

import com.migratorydata.authorization.common.config.Util;
import com.migratorydata.extensions.authorization.v2.client.StatusNotification;
import io.jsonwebtoken.*;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.migratorydata.authorization.hub.HubAuthorizationHandler.TOKEN_EXPIRED;
import static com.migratorydata.authorization.hub.HubAuthorizationHandler.TOKEN_INVALID;

public class Token {
    private final String token;
    private StatusNotification errorNotification = null;
    private Jws<Claims> jwsClaims = null;
    private Permissions permissions = null;

    private String appId;

    public Token(String token) {
        this.token = token;
    }

    public boolean parseToken(JwtParser jwtParser) {
        try {
            jwsClaims = jwtParser.parseClaimsJws(token);
            permissions = new Permissions((Map<String, List<String>>) jwsClaims.getBody().get(Util.PERMISSIONS_FIELD));
            if (jwsClaims.getBody().containsKey(Util.APPID_FIELD)) {
                appId = (String) jwsClaims.getBody().get(Util.APPID_FIELD);
            }
        } catch (MalformedJwtException e1) {
            e1.printStackTrace();
            errorNotification = TOKEN_INVALID;
        } catch (JwtException ex) {
            ex.printStackTrace();
            errorNotification = TOKEN_EXPIRED;
        } catch (Exception e) {
            e.printStackTrace();
            errorNotification = TOKEN_INVALID;
        }
        return (errorNotification == null);
    }

    public StatusNotification getErrorNotification() {
        return errorNotification;
    }

    public boolean authorizeSubscribe(String topic) {
        Permissions.Permission permission = permissions.getPermission(topic);
        if (permission != null && (permission == Permissions.Permission.SUB || permission == Permissions.Permission.ALL)) {
            return true;
        }
        return false;
    }

    public boolean authorizePublish(String topic) {
        Permissions.Permission permission = permissions.getPermission(topic);
        if ((permission == Permissions.Permission.PUB || permission == Permissions.Permission.ALL)) {
            return true;
        }
        return false;
    }

    public boolean isTimeToRenew(long millisBeforeRenewal) {
        Date currentTime = new Date();
        long currentTimeMillis = currentTime.getTime();
        Date time = new Date(currentTimeMillis + millisBeforeRenewal);
        if (time.after(getExpirationTime())) {
            return true;
        }
        return false;
    }

    public String getAppId() {
        return appId;
    }

    public String getId() {
        return jwsClaims.getBody().getId();
    }

    public Date getExpirationTime() {
        return jwsClaims.getBody().getExpiration();
    }
}
