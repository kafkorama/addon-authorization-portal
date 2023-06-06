package com.migratorydata.authorization.hub.api;

import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

import java.nio.charset.Charset;
import java.util.*;

public class Limit {

    private Map<String, Connection> connectionsPerServer = new HashMap<>();
    private BloomFilter<String> subjectsContainer;

    private long connections;
    private long messages;
    private long subjects;

    private long liveConnections = 0;
    private long messagesNumber = 0;

    public Limit(long connections, long messages, long subjects) {
        this.connections = connections;
        this.messages = messages;
        this.subjects = subjects;

        this.subjectsContainer = BloomFilter.create(
                Funnels.stringFunnel(Charset.defaultCharset()),
                subjects + ((10 * subjects) / 100),
                0.01);
    }

    public void updateConnections(String serverName, Integer nrConnections) {
        Connection connection = connectionsPerServer.get(serverName);
        if (connection == null) {
            connection = new Connection();
            connectionsPerServer.put(serverName, connection);
        }
        connection.setConnections(nrConnections);

        liveConnections = 0;

        List<String> servers = null;
        for (Map.Entry<String, Connection> entry : connectionsPerServer.entrySet()) {
            if (System.currentTimeMillis() - entry.getValue().getLastUpdate() < 16000) {
                liveConnections += entry.getValue().getConnections();
            } else {
                if (servers == null) {
                    servers = new ArrayList<>();
                }
                servers.add(entry.getKey());
            }
        }

        if (servers != null) {
            for (String s : servers) {
                connectionsPerServer.remove(s);
            }
        }
    }

    public void addMessages(int messagesNumber) {
        this.messagesNumber += messagesNumber;
    }

    public boolean isConnectionLimitExceeded() {
        if (liveConnections > connections) {
            return true;
        }
        return false;
    }

    private boolean isMessagesLimitExceeded() {
        if (messagesNumber > messages) {
            return true;
        }
        return false;
    }

    private boolean isSubjectsLimitExceeded(String subject) {
        if (subjectsContainer.mightContain(subject)) {
            return false;
        }
        if (subjectsContainer.approximateElementCount() >= subjects) {
            return true;
        }

        subjectsContainer.put(subject);
        return false;
    }

    public void resetMessagesNumber() {
        messagesNumber = 0;
    }

    public boolean isSubscribeLimitsExceeded(String subject) {
        if (isSubjectsLimitExceeded(subject)) {
            return true;
        }
        return false;
    }

    public boolean isPublishLimitsExceeded(String subject) {
        if (isMessagesLimitExceeded()) {
            return true;
        }
        if (isSubjectsLimitExceeded(subject)) {
            return true;
        }
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Limit limit = (Limit) o;
        return connections == limit.connections &&
                messages == limit.messages &&
                subjects == limit.subjects;
    }

    @Override
    public int hashCode() {
        return Objects.hash(connections, messages, subjects);
    }

    public int getNumberOfSubjects() {
        return (int)subjectsContainer.approximateElementCount();
    }

    public void updateLimit(Limit limit) {
        if (!this.equals(limit)) {
            this.connections = limit.connections;
            this.subjects = limit.subjects;
            this.messages = limit.messages;
            this.subjectsContainer = BloomFilter.create(
                    Funnels.stringFunnel(Charset.defaultCharset()),
                    subjects + ((10 * subjects) / 100),
                    0.01);
        }
    }
}
