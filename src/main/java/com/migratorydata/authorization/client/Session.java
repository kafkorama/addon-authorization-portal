package com.migratorydata.authorization.client;

import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import com.migratorydata.authorization.token.Token;
import com.migratorydata.extensions.authorization.v2.client.Client;
import static com.migratorydata.authorization.AuthorizationHandler.TOKEN_TO_EXPIRE;

public class Session {
    private Client client;
    private Token token;
    private Set<String> subscriptions = new HashSet<>(); // The set of subjects this client is subscribed to

    // Track the state and timestamp of token renewal
    private volatile boolean isTokenRenewalInProgress = false;
    private long tokenRenewalStartTimestamp;

    // Comparator for ordering sessions by their token expiration time
    public static final Comparator<Session> ORDER_BY_TOKEN_EXPIRATION_TIME = Comparator.comparing(Session::getTokenExpirationTime);

    // Comparator for ordering sessions by their token renewal start timestamp
    public static final Comparator<Session> ORDER_BY_TOKEN_RENEWAL_TIMESTAMP = Comparator.comparingLong(Session::getTokenRenewalStartTimestamp);

    public Session(Client client, Token token) {
        this.client = client;
        this.token = token;
    }

    public void startTokenRenewal() {
        isTokenRenewalInProgress = true;
        tokenRenewalStartTimestamp = System.currentTimeMillis();
        client.sendStatusNotification(TOKEN_TO_EXPIRE);
    }

    public void completeTokenRenewal() {
        isTokenRenewalInProgress = false;
    }

    public boolean hasTokenRenewalCompleted() {
        return isTokenRenewalInProgress == false;
    }

    public boolean hasTokenRenewalTimedOut(long currentTimeMillis, long millisBeforeRenewal) {
        return (currentTimeMillis - tokenRenewalStartTimestamp) > millisBeforeRenewal;
    }

    public boolean isTimeToRenewToken(long millisBeforeRenewal) {
        Date currentTime = new Date();
        long currentTimeMillis = currentTime.getTime();
        Date time = new Date(currentTimeMillis + millisBeforeRenewal);
        if (time.after(token.getExpirationTime())) {
            return true;
        }
        return false;
    }

    public long getTokenRenewalStartTimestamp() {
        return tokenRenewalStartTimestamp;
    }

    public Date getTokenExpirationTime() {
        return token.getExpirationTime();
    }

    public Token getToken() {
        return token;
    }

    public String getClientAddress() {
        return client.getClientAddress();
    }

    public void addSubscription(String subject) {
        subscriptions.add(subject);
    }

    public void disconnect() {
        client.disconnect();
    }
}
