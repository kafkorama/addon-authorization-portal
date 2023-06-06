package com.migratorydata.authorization.hub;

import com.migratorydata.authorization.common.config.Util;
import com.migratorydata.authorization.helper.ClientCredentials;
import com.migratorydata.authorization.helper.EventConnect;
import com.migratorydata.authorization.helper.EventPublish;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static com.migratorydata.authorization.token.SessionOrderTest.generateToken;

public class EventPublishTest extends EventBase {

    private String clientAddress = "127.0.0.1:35274";
    private String subject = "/s/s";
    private String expiredToken = generateToken(-100);

    // subject /s/s has permission for publish and subscribe
    private String validToken = generateToken(100);

    // subject /s/s has permission for publish
    private String validTokenWithPublishPermission = generateToken(100, subject, Util.PUB_FIELD);

    // subject /s/s has permission for subscribe
    private String validTokenWithSubscribePermission = generateToken(100, subject, Util.SUB_FIELD);

    // subject /* has permission for ALL
    private String validTokenWithWildcardPermission = generateToken(100, "/*", Util.ALL_FIELD);

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
        ClientCredentials clientCredentials = new ClientCredentials(null, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        authorizationListener.onClientConnect(eventConnect);

        EventPublish eventPublish = new EventPublish(clientCredentials, subject);
        authorizationListener.onClientPublish(eventPublish);

        Assert.assertFalse(eventPublish.getPermission());
    }

    @Test
    public void test_expired_token() {
        ClientCredentials clientCredentials = new ClientCredentials(expiredToken, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        authorizationListener.onClientConnect(eventConnect);

        EventPublish eventPublish = new EventPublish(clientCredentials, subject);
        authorizationListener.onClientPublish(eventPublish);

        Assert.assertFalse(eventPublish.getPermission());
    }

    @Test
    public void test_valid_token() {
        ClientCredentials clientCredentials = new ClientCredentials(validToken, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        authorizationListener.onClientConnect(eventConnect);

        EventPublish eventPublish = new EventPublish(clientCredentials, subject);
        authorizationListener.onClientPublish(eventPublish);

        Assert.assertTrue(eventPublish.getPermission());
    }

    @Test
    public void test_valid_token_without_subject_permission() {
        String subjectWithoutPermission = "/s/s2";

        ClientCredentials clientCredentials = new ClientCredentials(validToken, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        authorizationListener.onClientConnect(eventConnect);

        EventPublish eventPublish = new EventPublish(clientCredentials, subjectWithoutPermission);
        authorizationListener.onClientPublish(eventPublish);

        Assert.assertFalse(eventPublish.getPermission());
    }

    @Test
    public void test_valid_token_with_publish_permission() {
        ClientCredentials clientCredentials = new ClientCredentials(validTokenWithPublishPermission, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        authorizationListener.onClientConnect(eventConnect);

        EventPublish eventPublish = new EventPublish(clientCredentials, subject);
        authorizationListener.onClientPublish(eventPublish);

        Assert.assertTrue(eventPublish.getPermission());
    }

    @Test
    public void test_valid_token_with_subscribe_permission() {
        ClientCredentials clientCredentials = new ClientCredentials(validTokenWithSubscribePermission, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        authorizationListener.onClientConnect(eventConnect);

        EventPublish eventPublish = new EventPublish(clientCredentials, subject);
        authorizationListener.onClientPublish(eventPublish);

        Assert.assertFalse(eventPublish.getPermission());
    }

    @Test
    public void test_wildcard_token_with_all_permission() {
        ClientCredentials clientCredentials = new ClientCredentials(validTokenWithWildcardPermission, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        authorizationListener.onClientConnect(eventConnect);

        EventPublish eventPublish = new EventPublish(clientCredentials, subject);
        authorizationListener.onClientPublish(eventPublish);

        Assert.assertTrue(eventPublish.getPermission());
    }

}
