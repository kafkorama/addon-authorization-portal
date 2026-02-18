package com.migratorydata.authorization;

import com.migratorydata.authorization.client.Session;
import com.migratorydata.authorization.token.Token;
import com.migratorydata.authorization.token.TokenExpirationHandler;
import com.migratorydata.authorization.config.Util;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;
import com.migratorydata.extensions.authorization.v2.client.*;
import io.jsonwebtoken.JwtParser;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
public class AuthorizationHandler implements MigratoryDataAuthorizationListener {
    public static final StatusNotification TOKEN_VALID = new StatusNotification("NOTIFY_TOKEN_VALID", "NOTIFY_TOKEN_VALID");
    public static final StatusNotification TOKEN_EXPIRED = new StatusNotification("NOTIFY_TOKEN_EXPIRED", "NOTIFY_TOKEN_EXPIRED");
    public static final StatusNotification TOKEN_TO_EXPIRE = new StatusNotification("NOTIFY_TOKEN_TO_EXPIRE", "NOTIFY_TOKEN_TO_EXPIRE");
    public static final StatusNotification TOKEN_INVALID = new StatusNotification("NOTIFY_TOKEN_INVALID", "NOTIFY_TOKEN_INVALID");
    public static final StatusNotification TOKEN_UPDATED = new StatusNotification("NOTIFY_TOKEN_UPDATED", "NOTIFY_TOKEN_UPDATED");

    private JwtParser jwtParser;
    private final String urlRevokedTokens;
    private final String urlSigningKeys;

    private Set<String> revokedTokens = new HashSet<>(); // token_id (jti)
    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    private final Map<String, Session> sessionsByIpAddress = new HashMap<>();
    private Map<String, JwtParser> jwtParsers = new HashMap<>(); // uuid to JwtParser
    private final TokenExpirationHandler tokenExpirationHandler;

    public AuthorizationHandler(long millisBeforeRenewal, JwtParser jwtParser, String urlRevokedTokens, String urlSigningKeys) {
        this.tokenExpirationHandler = new TokenExpirationHandler(millisBeforeRenewal);
        this.jwtParser = jwtParser;
        this.urlRevokedTokens = urlRevokedTokens;
        this.urlSigningKeys = urlSigningKeys;

        executor.scheduleAtFixedRate(() -> {
            // load revoked tokens from api hub
            offer(this::updateRevokedTokens);
            offer(this::updateSigningKeys);
        }, 5, 60, TimeUnit.SECONDS);
    }

    private void updateSigningKeys() {
        JSONArray signingKeys = Util.fetchFromUrl(urlSigningKeys);
        if (signingKeys == null || signingKeys.isEmpty()) {
            return;
        }
        for (int i = 0; i < signingKeys.length(); i++) {
            JSONObject jwtToken = signingKeys.getJSONObject(i);
            String signingKeyId = jwtToken.getString("uuid");
            String signingKey = jwtToken.getString("signKey");

            if (jwtParsers.containsKey(signingKeyId)) {
                continue; // signing key already exists
            }
            JwtParser jwtParser = Util.createJwtParser(signingKey);
            jwtParsers.put(signingKeyId, jwtParser);
        }
    }

    private void updateRevokedTokens() {
        JSONArray jwtTokens = Util.fetchFromUrl(urlRevokedTokens); // get the list of the JWT IDs of the revoked tokens
        if (jwtTokens == null || jwtTokens.isEmpty()) {
            return;
        }
        for (int i = 0; i < jwtTokens.length(); i++) {
            revokedTokens.add(jwtTokens.getString(i));
        }
    }

    @Override
    public void onClientConnect(EventConnect eventConnect) {
        String jwtToken = eventConnect.getClient().getToken();
        if (jwtToken == null || jwtToken.isEmpty()) {
            eventConnect.authorize(false, TOKEN_INVALID.getStatus());
            return; // no token provided
        }

        JwtParser jwtParser = this.jwtParser;
        String signingKeyId = (String) Util.getClaimsWithoutVerification(jwtToken).get(Token.SIGNING_KEY_ID_FIELD);
        if (signingKeyId != null && jwtParsers.containsKey(signingKeyId)) {
            jwtParser = jwtParsers.get(signingKeyId);
        }

        Token token = new Token(jwtToken);
        StatusNotification tokenStatus = token.parseToken(jwtParser);
        if (TOKEN_VALID.getStatus().equals(tokenStatus.getStatus())) {
            Session session = new Session(eventConnect.getClient(), token);
            tokenExpirationHandler.add(session);
            sessionsByIpAddress.put(session.getClientAddress(), session);

            eventConnect.authorize(true, tokenStatus.getStatus());
        } else {
            eventConnect.authorize(false, tokenStatus.getStatus());
        }
    }

    @Override
    public void onClientUpdateToken(EventUpdateToken eventUpdateToken) { // TODO: check token, check same app
        String jwtToken = eventUpdateToken.getClient().getToken();
        if (jwtToken == null || jwtToken.isEmpty()) {
            eventUpdateToken.getClient().sendStatusNotification(TOKEN_INVALID);
            return; // no token provided
        }

        JwtParser jwtParser = this.jwtParser;
        String signingKeyId = (String) Util.getClaimsWithoutVerification(jwtToken).get(Token.SIGNING_KEY_ID_FIELD);
        if (signingKeyId != null && jwtParsers.containsKey(signingKeyId)) {
            jwtParser = jwtParsers.get(signingKeyId);
        }

        Token token = new Token(jwtToken);
        StatusNotification tokenStatus = token.parseToken(jwtParser);
        if (TOKEN_VALID.getStatus().equals(tokenStatus.getStatus())) {
            Session session = new Session(eventUpdateToken.getClient(), token);
            tokenExpirationHandler.add(session);
            Session previousSession = sessionsByIpAddress.put(session.getClientAddress(), session);
            if (previousSession != null) {
                previousSession.completeTokenRenewal();
            }
            eventUpdateToken.getClient().sendStatusNotification(TOKEN_UPDATED);
        } else {
            eventUpdateToken.getClient().sendStatusNotification(tokenStatus);
        }
    }

    @Override
    public void onClientSubscribe(EventSubscribe eventSubscribe) {
        Map<String, Boolean> permissions = new HashMap<String, Boolean>();

        Session session = sessionsByIpAddress.get(eventSubscribe.getClient().getClientAddress());
        if (session != null && !revokedTokens.contains(session.getToken().getId())) {
            for (String subject : eventSubscribe.getSubjects()) {
                boolean hasSubscribePermission = session.getToken().authorizeSubscribe(subject);
                permissions.put(subject, hasSubscribePermission);
                if (hasSubscribePermission) {
                    session.addSubscription(subject);
                }
            }
        }

        eventSubscribe.authorize(permissions);
    }

    @Override
    public void onClientPublish(EventPublish eventPublish) {
        boolean permission = false;

        Session session = sessionsByIpAddress.get(eventPublish.getClient().getClientAddress());
        if (session != null && !revokedTokens.contains(session.getToken().getId())) {
            String subject = eventPublish.getSubject();
            if (session.getToken().authorizePublish(subject)) {
                permission = true;
            }
        }

        eventPublish.authorize(permission);
    }

    @Override
    public void onClientDisconnect(EventDisconnect eventDisconnect) {
        Session session = sessionsByIpAddress.remove(eventDisconnect.getClient().getClientAddress());
        if (session != null) {
            tokenExpirationHandler.remove(session);
        }
    }

    @Override
    public void onInit() {
    }

    @Override
    public void onDispose() {
    }

    public void offer(Runnable r) {
        executor.execute(() -> {
            try {
                r.run();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

}
