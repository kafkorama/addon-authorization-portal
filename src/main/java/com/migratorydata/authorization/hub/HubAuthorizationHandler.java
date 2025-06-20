package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.common.client.Session;
import com.migratorydata.authorization.common.token.Token;
import com.migratorydata.authorization.common.token.TokenExpirationHandler;
import com.migratorydata.authorization.hub.api.Api;
import com.migratorydata.authorization.hub.common.CommonUtils;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;
import com.migratorydata.extensions.authorization.v2.client.*;
import io.jsonwebtoken.JwtParser;
import org.json.JSONArray;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class HubAuthorizationHandler implements MigratoryDataAuthorizationListener {

    public static final StatusNotification TOKEN_EXPIRED = new StatusNotification("NOTIFY_TOKEN_EXPIRED", "NOTIFY_TOKEN_EXPIRED");
    public static final StatusNotification TOKEN_TO_EXPIRE = new StatusNotification("NOTIFY_TOKEN_TO_EXPIRE", "NOTIFY_TOKEN_TO_EXPIRE");
    public static final StatusNotification TOKEN_INVALID = new StatusNotification("NOTIFY_TOKEN_INVALID", "NOTIFY_TOKEN_INVALID");
    public static final StatusNotification TOKEN_UPDATED = new StatusNotification("NOTIFY_TOKEN_UPDATED", "NOTIFY_TOKEN_UPDATED");
    public static final StatusNotification NOTIFY_CONNECTIONS_LIMIT_REACHED = new StatusNotification("NOTIFY_CONNECTIONS_LIMIT_REACHED", "NOTIFY_CONNECTIONS_LIMIT_REACHED");

    private Map<String, Api> applications = new HashMap<>(); // app_id to application
    private Set<String> revokedTokens = new HashSet<>(); // token_id (jti)
    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private final Map<String, Session> sessions = new HashMap<>();
    private final TokenExpirationHandler tokenExpirationHandler;
    private JwtParser jwtVerifyParser;

    private final String urlRevokedTokens;

    public HubAuthorizationHandler(long millisBeforeRenewal, JwtParser jwtVerifyParser, String urlRevokedTokens) {

        this.tokenExpirationHandler = new TokenExpirationHandler(millisBeforeRenewal);

        this.jwtVerifyParser = jwtVerifyParser;
        this.urlRevokedTokens = urlRevokedTokens;

        executor.scheduleAtFixedRate(() -> {
            // load revoked tokens from api hub
            offer(this::updateRevokedTokens);
        }, 5, 60, TimeUnit.SECONDS);
    }

    private void updateRevokedTokens() {
        JSONArray revokedTokensJson = CommonUtils.getRequest(urlRevokedTokens);

        if (revokedTokensJson == null) {
            return;
        }

        //System.out.println(revokedTokensJson.toString());

        if (revokedTokensJson.isEmpty()) {
            return;
        }

        for (int i = 0; i < revokedTokensJson.length(); i++) {
            revokedTokens.add(revokedTokensJson.getString(i));
        }
    }

    @Override
    public void onClientConnect(EventConnect eventConnect) {
        Token token = new Token(eventConnect.getClient().getToken());
        if (token.parseToken(jwtVerifyParser)) {
            Session session = new Session(eventConnect.getClient(), token);

            String appid = session.getToken().getAppId();

            Api application = applications.get(appid);
            if (application == null) {
                application = new Api(appid);
                applications.put(appid, application);
            }

            sessions.put(session.getClientAddress(), session);
            tokenExpirationHandler.add(session);
            eventConnect.authorize(true, "TOKEN_VALID");

        } else {
            eventConnect.authorize(false, token.getErrorNotification().getStatus());
        }
    }

    @Override
    public void onClientUpdateToken(EventUpdateToken eventUpdateToken) {

        // check token
        // check same app
        Token token = new Token(eventUpdateToken.getClient().getToken());
        if (token.parseToken(jwtVerifyParser)) {
            Session session = new Session(eventUpdateToken.getClient(), token);
            tokenExpirationHandler.add(session);
            Session previousSession = sessions.put(session.getClientAddress(), session);
            if (previousSession != null) {
                previousSession.setTokenRenewalCompleted();
            }
            eventUpdateToken.getClient().sendStatusNotification(TOKEN_UPDATED);
        } else {
            eventUpdateToken.getClient().sendStatusNotification(token.getErrorNotification());
        }
    }

    @Override
    public void onClientSubscribe(EventSubscribe eventSubscribe) {

        Map<String, Boolean> permissions = new HashMap<String, Boolean>();
        Session session = sessions.get(eventSubscribe.getClient().getClientAddress());
        if (session != null) {

            if (revokedTokens.contains(session.getToken().getId())) {
                eventSubscribe.authorize(permissions);
                return;
            }

            String appid = session.getToken().getAppId();

            Api application = applications.get(appid);
            if (application == null) {
                application = new Api(appid);
                applications.put(appid, application);
            }

            List<String> subscribeSubjects = new ArrayList<>();
            for (String subject : eventSubscribe.getSubjects()) {

                boolean subjectAuthorized = session.getToken().authorizeSubscribe(subject);
                permissions.put(subject, subjectAuthorized);

                if (subjectAuthorized) {
                    subscribeSubjects.add(subject);
                    session.setSubscribeSubject(subject);
                }
            }
        }
        eventSubscribe.authorize(permissions);
    }

    @Override
    public void onClientPublish(EventPublish eventPublish) {
        //logger.info("PUBLISH check=" + eventPublish);

        boolean permission = false;
        Session session = sessions.get(eventPublish.getClient().getClientAddress());
        if (session != null) {

            if (revokedTokens.contains(session.getToken().getId())) {
                eventPublish.authorize(false);
                return;
            }

            String appid = session.getToken().getAppId();

            Api application = applications.get(appid);
            if (application == null) {
                application = new Api(appid);
                applications.put(appid, application);
            }

            String subject = eventPublish.getSubject();

            if (session.getToken().authorizePublish(subject)) {
                permission = true;
            }
        }
        eventPublish.authorize(permission);
    }

    @Override
    public void onClientDisconnect(EventDisconnect eventDisconnect) {
        Session session = sessions.remove(eventDisconnect.getClient().getClientAddress());
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
