package com.migratorydata.authorization.token;

import com.migratorydata.authorization.common.client.Session;
import com.migratorydata.authorization.common.token.Token;
import com.migratorydata.authorization.common.token.TokenExpirationHandler;
import com.migratorydata.authorization.helper.ClientCredentials;
import com.migratorydata.authorization.hub.HubAuthorizationHandler;
import org.junit.Assert;
import org.junit.Test;

import static com.migratorydata.authorization.token.SessionOrderTest.generateToken;
import static com.migratorydata.authorization.token.SessionOrderTest.jwtVerifyParser;

public class TokenExpirationHandlerTest {

    @Test
    public void test_send_notification_when_token_is_about_to_expire() throws InterruptedException {
        TokenExpirationHandler tokenExpirationHandler = new TokenExpirationHandler(5 * 1000);

        Token t1 = new Token(generateToken(4));
        t1.parseToken(jwtVerifyParser);

        ClientCredentials client1 = new ClientCredentials(null, null);

        Session s1 = new Session(client1, t1);

        tokenExpirationHandler.add(s1);

        Thread.sleep(2000);

        Assert.assertTrue(client1.getNotification().getStatus().equals(HubAuthorizationHandler.TOKEN_TO_EXPIRE.getStatus()));

        Thread.sleep(5000);

        Assert.assertTrue(client1.isDisconnect());
    }

    @Test
    public void test_send_notification_when_token_is_about_to_expire_and_renew_token() throws InterruptedException {
        TokenExpirationHandler tokenExpirationHandler = new TokenExpirationHandler(5 * 1000);

        Token t1 = new Token(generateToken(4));
        t1.parseToken(jwtVerifyParser);

        ClientCredentials client1 = new ClientCredentials(null, null);

        Session s1 = new Session(client1, t1);

        tokenExpirationHandler.add(s1);

        Thread.sleep(2000);

        Assert.assertTrue(client1.getNotification().getStatus().equals(HubAuthorizationHandler.TOKEN_TO_EXPIRE.getStatus()));

        s1.setTokenRenewalCompleted();

        Thread.sleep(5000);

        Assert.assertFalse(client1.isDisconnect());
    }

}
