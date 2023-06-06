package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.helper.ClientCredentials;
import com.migratorydata.authorization.helper.EventDisconnect;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class EventDisconnectTest extends EventBase {

    // Tokens are generated with demo key from configuration file
    // authorization.security.secret_key=nR7Xgg5+DV9kIqNyynwv5dtLeAM97cBcBewW8pr0DMc
    private String clientAddress = "127.0.0.1:35274";

    @Before
    public void onStart() {
        initialize();
    }

    @After
    public void onDispose() {
        authorizationListener.onDispose();
    }

    @Test
    public void test() {
        EventDisconnect eventDisconnect = new EventDisconnect(new ClientCredentials(null, clientAddress));
        authorizationListener.onClientDisconnect(eventDisconnect);
        Assert.assertTrue(true);
    }

}
