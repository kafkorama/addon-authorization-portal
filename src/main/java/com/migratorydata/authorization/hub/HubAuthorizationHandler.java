package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.common.client.Session;
import com.migratorydata.authorization.common.token.Token;
import com.migratorydata.authorization.common.token.TokenExpirationHandler;
import com.migratorydata.authorization.hub.api.Api;
import com.migratorydata.authorization.hub.api.Limit;
import com.migratorydata.authorization.hub.common.CommonUtils;
import com.migratorydata.authorization.hub.common.Metric;
import com.migratorydata.authorization.hub.common.Producer;
import com.migratorydata.authorization.hub.limits.LimitsAgregationHandler;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;
import com.migratorydata.extensions.authorization.v2.client.*;
import io.jsonwebtoken.JwtParser;
import org.json.JSONArray;
import org.json.JSONObject;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.migratorydata.authorization.common.config.Util.toEpochNanos;

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

    private LimitsAgregationHandler limitsAgregationHandler;

    private final String urlRevokedTokens;
    private final String urlApiLimits;

    public HubAuthorizationHandler(Producer producer, String topicStats, String serverName, long millisBeforeRenewal,
                                   JwtParser jwtVerifyParser, String urlRevokedTokens, String urlApiLimits, int numberOfClusterMembers) {

        this.limitsAgregationHandler = new LimitsAgregationHandler(producer, serverName, topicStats, numberOfClusterMembers);

        this.tokenExpirationHandler = new TokenExpirationHandler(millisBeforeRenewal);

        this.jwtVerifyParser = jwtVerifyParser;
        this.urlRevokedTokens = urlRevokedTokens;
        this.urlApiLimits = urlApiLimits;

        LocalDateTime start = LocalDateTime.now();
        LocalDateTime end = start.plusHours(1).truncatedTo(ChronoUnit.HOURS);

        Duration duration = Duration.between(start, end);
        long nextHour = duration.getSeconds();

        executor.scheduleAtFixedRate(() -> {
            offer(() -> {
                // reset messages limit every hour
                for (Map.Entry<String, Api> entry : applications.entrySet()) {
                    entry.getValue().getLimit().resetMessagesNumber();
                }
            });
        }, nextHour, 3600, TimeUnit.SECONDS);

        executor.scheduleAtFixedRate(() -> {
            // load revoked tokens from api hub
            offer(this::updateRevokedTokens);
        }, 5, 60, TimeUnit.SECONDS);

        executor.scheduleAtFixedRate(() -> {
            offer(() -> {
                updateLimits(getApiLimits());
            });
        }, 5, 180, TimeUnit.SECONDS);

        executor.scheduleAtFixedRate(() -> {
            offer(() -> {
                if (applications.size() > 0) {
                    JSONObject metricStats = new JSONObject();

                    metricStats.put("up", "sbj");
                    metricStats.put("server", serverName);
                    metricStats.put("timestamp", toEpochNanos(Instant.now()));

                    JSONArray metrics = new JSONArray();
                    for (Map.Entry<String, Api> app : applications.entrySet()) {
                        JSONObject metric = new JSONObject();
                        metric.put("appid", app.getValue().getApiId());
                        metric.put("sbj", app.getValue().getLimit().getNumberOfSubjects());
                        metric.put("con", 0);
                        metric.put("msg", 0);
                        metrics.put(metric);
                    }
                    metricStats.put("metrics", metrics);

                    producer.write(topicStats, metricStats.toString().getBytes());
                }
            });
        }, 10, 5, TimeUnit.SECONDS);

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

    public JSONArray getApiLimits() {
        return CommonUtils.getRequest(urlApiLimits);
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
            if (application.getLimit().isConnectionLimitExceeded()) {
                System.out.printf("[%1$s] %2$s", "MANAGER_THREAD", "Connections Limit reached for user with token=" + eventConnect.getClient().getToken()  + " , and appid=" + application.getApiId());
                eventConnect.authorize(false, NOTIFY_CONNECTIONS_LIMIT_REACHED.getStatus());
                return;
            }

            sessions.put(session.getClientAddress(), session);
            tokenExpirationHandler.add(session);
            eventConnect.authorize(true, "TOKEN_VALID");

            limitsAgregationHandler.onConnect(session.getToken().getAppId());
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
                // check if subjects limit exceeded
                if (application.getLimit().isSubscribeLimitsExceeded(subject)) {
                    System.out.printf("[%1$s] %2$s", "MANAGER_THREAD", "Subjects Limit reached for user with subject=" + subject);

                    permissions.put(subject, false);
                    continue;
                }

                boolean subjectAuthorized = session.getToken().authorizeSubscribe(subject);
                permissions.put(subject, subjectAuthorized);

                if (subjectAuthorized) {
                    subscribeSubjects.add(subject);
                    session.setSubscribeSubject(subject);
                }
            }

            if (subscribeSubjects.size() > 0) {
                limitsAgregationHandler.onSubscribe(appid, subscribeSubjects);
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

            // check if publish limit exceeded
            if (application.getLimit().isPublishLimitsExceeded(subject)) {
                System.out.printf("[%1$s] %2$s", "MANAGER_THREAD", "Messages Limit reached for user with subject=" + subject);

                eventPublish.authorize(false);
                return;
            }

            if (session.getToken().authorizePublish(subject)) {
                permission = true;
                limitsAgregationHandler.onPublish(appid, subject);
            }
        }
        eventPublish.authorize(permission);
    }

    @Override
    public void onClientDisconnect(EventDisconnect eventDisconnect) {
        Session session = sessions.remove(eventDisconnect.getClient().getClientAddress());
        if (session != null) {
            limitsAgregationHandler.onDisconnect(session.getToken().getAppId());
            tokenExpirationHandler.remove(session);

            limitsAgregationHandler.onUnsubscribe(session.getToken().getAppId(), session.getSubscribeSubjects());
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

    public void updateLimits(JSONArray applicationsLimit) {

        if (applicationsLimit == null) {
            return;
        }

        for (int i = 0; i < applicationsLimit.length(); i++) {
            JSONObject app = applicationsLimit.getJSONObject(i);
            String appid = app.getString("appId");

            if (applications.containsKey(appid) == false) {
                applications.put(appid, new Api(appid));
            }

            applications.get(appid).updateLimit(new Limit(app.getJSONObject("limit").getInt("connections"), app.getJSONObject("limit").getInt("messages"), app.getJSONObject("limit").getInt("subjects")));
        }
    }

    public void updateMetrics(Map<String, Metric> metricsMap, String serverName, String update) {
        offer(() -> {
            for (Map.Entry<String, Metric> entry : metricsMap.entrySet()) {
                Api application = applications.get(entry.getKey());
                if (application != null && "con_msg".equals(update)) {
                    application.getLimit().updateConnections(serverName, entry.getValue().connections);
                    application.getLimit().addMessages(entry.getValue().messages);
                }
            }
        });
    }

}
