package com.migratorydata.authorization.common.token;

import com.migratorydata.authorization.common.client.Session;

import java.util.Comparator;
import java.util.Iterator;
import java.util.TreeSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.migratorydata.authorization.hub.HubAuthorizationHandler.TOKEN_TO_EXPIRE;

public class TokenExpirationHandler {
    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    private final TreeSet<Session> sessions = new TreeSet<>(new SessionOrderByExpirationTime());
    private final TreeSet<Session> disconnectSessions = new TreeSet<>(new SessionOrderByTokenRenewalTimestamp());
    private final long millisBeforeRenewal;

    public TokenExpirationHandler(long millisBeforeRenewal) {
        this.millisBeforeRenewal = millisBeforeRenewal;

        executor.scheduleAtFixedRate(() -> {
            handleTokenExpiration();
            handleTokenRenewal();
        }, 1000, 200, TimeUnit.MILLISECONDS);
    }

    private void handleTokenExpiration() {
        Iterator<Session> itSessions = sessions.iterator();
        while (itSessions.hasNext()) {
            Session session = itSessions.next();
            if (session.getToken().isTimeToRenew(millisBeforeRenewal)) {
                session.sendStatusNotification(TOKEN_TO_EXPIRE);
                session.startTokenRenewal();
                itSessions.remove();

                disconnectSessions.add(session);
            } else {
                break;
            }
        }
    }

    private void handleTokenRenewal() {
        long currentTimeMillis = System.currentTimeMillis();
        Iterator<Session> itDisconnectSessions = disconnectSessions.iterator();
        while (itDisconnectSessions.hasNext()) {
            Session session = itDisconnectSessions.next();
            if (session.isTokenRenewalCompleted()) {
                itDisconnectSessions.remove();
                continue;
            }
            if (session.hasTokenRenewalTimedOut(currentTimeMillis, millisBeforeRenewal)) {
                session.disconnect();
                itDisconnectSessions.remove();
            } else {
                break;
            }
        }
    }

    public void add(Session session) {
        executor.execute(() -> {
            sessions.add(session);
        });
    }

    public void remove(Session session) {
        executor.execute(() -> {
            sessions.remove(session);
            disconnectSessions.remove(session);
        });
    }

    public static class SessionOrderByExpirationTime implements Comparator<Session> {

        @Override
        public int compare(Session s1, Session s2) {
            return s1.getToken().getExpirationTime().compareTo(s2.getToken().getExpirationTime());
        }
    }

    public static class SessionOrderByTokenRenewalTimestamp implements Comparator<Session> {
        @Override
        public int compare(Session o1, Session o2) {
            if (o1.getTokenRenewalTimestamp() < o2.getTokenRenewalTimestamp()) {
                return -1;
            } else if (o1.getTokenRenewalTimestamp() > o2.getTokenRenewalTimestamp()) {
                return 1;
            }
            return 0;
        }
    }
}
