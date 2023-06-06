package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.helper.ClientCredentials;
import com.migratorydata.authorization.helper.EventConnect;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static com.migratorydata.authorization.hub.HubAuthorizationHandler.TOKEN_EXPIRED;
import static com.migratorydata.authorization.hub.HubAuthorizationHandler.TOKEN_INVALID;
import static com.migratorydata.authorization.token.SessionOrderTest.generateToken;

public class EventConnectTest extends EventBase {

    private final String clientAddress = "127.0.0.1:35274";
    private final String expiredToken = generateToken(-100);
    private final String validToken = generateToken(100);

    @Before
    public void onStart() {
        initialize();
    }

    @After
    public void onDispose() {
        authorizationListener.onDispose();
    }

    @Test
    public void test_null_token() {
        EventConnect eventConnect = new EventConnect(new ClientCredentials(null, clientAddress));
        authorizationListener.onClientConnect(eventConnect);
        Assert.assertTrue(eventConnect.getReason() == TOKEN_INVALID.getStatus());
    }

    @Test
    public void test_empty_token() {
        EventConnect eventConnect = new EventConnect(new ClientCredentials("", clientAddress));
        authorizationListener.onClientConnect(eventConnect);
        Assert.assertTrue(eventConnect.getReason() == TOKEN_INVALID.getStatus());
    }

    @Test
    public void test_expired_token() {
        EventConnect eventConnect = new EventConnect(new ClientCredentials(expiredToken, clientAddress));
        authorizationListener.onClientConnect(eventConnect);
        Assert.assertTrue(eventConnect.getReason() == TOKEN_EXPIRED.getStatus());
    }

    @Test
    public void test_valid_token() {
        EventConnect eventConnect = new EventConnect(new ClientCredentials(validToken, clientAddress));
        authorizationListener.onClientConnect(eventConnect);
        Assert.assertTrue(eventConnect.getReason() == "TOKEN_VALID");
    }

}
