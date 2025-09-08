package com.migratorydata.authorization.token;

import com.migratorydata.authorization.client.Session;

import java.util.Iterator;
import java.util.TreeSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class TokenExpirationHandler {
    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private final TreeSet<Session> sessionsByExpiration = new TreeSet<>(Session.ORDER_BY_TOKEN_EXPIRATION_TIME);
    private final TreeSet<Session> sessionsAwaitingTokenRenewal = new TreeSet<>(Session.ORDER_BY_TOKEN_RENEWAL_TIMESTAMP);

    private final long millisBeforeRenewal;

    public TokenExpirationHandler(long millisBeforeRenewal) {
        this.millisBeforeRenewal = millisBeforeRenewal;

        executor.scheduleAtFixedRate(() -> {
            handleTokenExpiration();
            handleTokenRenewal();
        }, 1000, 200, TimeUnit.MILLISECONDS);
    }

    private void handleTokenExpiration() {
        Iterator<Session> sessionIterator = sessionsByExpiration.iterator();
        while (sessionIterator.hasNext()) {
            Session session = sessionIterator.next();
            if (session.isTimeToRenewToken(millisBeforeRenewal)) {
                session.startTokenRenewal();
                // the current session is moved to the list of sessions awaiting token renewal
                sessionIterator.remove();
                sessionsAwaitingTokenRenewal.add(session);
            } else {
                // Once we find a session that does not need token renewal,
                // all following sessions will not need it either, since they are ordered.
                break;
            }
        }
    }

    private void handleTokenRenewal() {
        long currentTimeMillis = System.currentTimeMillis();
        Iterator<Session> sessionIterator = sessionsAwaitingTokenRenewal.iterator();
        while (sessionIterator.hasNext()) {
            Session session = sessionIterator.next();
            if (session.hasTokenRenewalCompleted()) {
                // If the current session awaiting token renewal successfully renewed its token,
                // remove it from sessionsAwaitingTokenRenewal
                sessionIterator.remove();
                continue;
            }

            if (session.hasTokenRenewalTimedOut(currentTimeMillis, millisBeforeRenewal)) {
                // If the current session awaiting token renewal failed to renew its token,
                // i.e. token renewal timed out, then disconnect the client
                session.disconnect();
                sessionIterator.remove();
            } else {
                // Once we find a session awaiting token renewal that has not timed out,
                // we can stop, since the sessions are ordered.
                break;
            }
        }
    }

    public void add(Session session) {
        executor.execute(() -> {
            sessionsByExpiration.add(session);
        });
    }

    public void remove(Session session) {
        executor.execute(() -> {
            sessionsByExpiration.remove(session);
            sessionsAwaitingTokenRenewal.remove(session);
        });
    }
}
