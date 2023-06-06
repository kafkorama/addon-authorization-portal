package com.migratorydata.authorization.token;

import com.migratorydata.authorization.common.client.Session;
import com.migratorydata.authorization.common.token.Token;
import com.migratorydata.authorization.common.token.TokenExpirationHandler;
import com.migratorydata.authorization.common.config.Util;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.Assert;
import org.junit.Test;

import java.security.Key;
import java.util.*;

public class SessionOrderTest {

    public static String secretKey = "He39zDQW7RdkOcxe3L9qvoSQ/ef40BG6Ro4hrHDjE+U=";

    public static Key signKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    public static JwtParser jwtVerifyParser = Jwts.parserBuilder().setSigningKey(signKey).build();

    @Test
    public void test_expiration_date_order_comparator_reverse() {
        TreeSet<Session> sessions = new TreeSet<>(new TokenExpirationHandler.SessionOrderByExpirationTime());

        Token t1 = new Token(generateToken(100));
        t1.parseToken(jwtVerifyParser);

        Token t2 = new Token(generateToken(90));
        t2.parseToken(jwtVerifyParser);

        Token t3 = new Token(generateToken(80));
        t3.parseToken(jwtVerifyParser);

        Session s1 = new Session(null, t1);
        Session s2 = new Session(null, t2);
        Session s3 = new Session(null, t3);

        sessions.add(s1);
        sessions.add(s2);
        sessions.add(s3);

        Iterator<Session> it = sessions.iterator();

        Session testSession = it.next();
        while(it.hasNext()) {
            Session currentSession = it.next();
            Assert.assertTrue(testSession.getToken().getExpirationTime().before(currentSession.getToken().getExpirationTime()));

            testSession = currentSession;
        }
    }

    @Test
    public void test_expiration_date_order_comparator_random() {
        TreeSet<Session> sessions = new TreeSet<>(new TokenExpirationHandler.SessionOrderByExpirationTime());

        Token t1 = new Token(generateToken(100));
        t1.parseToken(jwtVerifyParser);

        Token t2 = new Token(generateToken(90));
        t2.parseToken(jwtVerifyParser);

        Token t3 = new Token(generateToken(110));
        t3.parseToken(jwtVerifyParser);

        Session s1 = new Session(null, t1);
        Session s2 = new Session(null, t2);
        Session s3 = new Session(null, t3);

        sessions.add(s1);
        sessions.add(s2);
        sessions.add(s3);

        Iterator<Session> it = sessions.iterator();

        Session testSession = it.next();
        while(it.hasNext()) {
            Session currentSession = it.next();
            Assert.assertTrue(testSession.getToken().getExpirationTime().before(currentSession.getToken().getExpirationTime()));

            testSession = currentSession;
        }
    }

    @Test
    public void test_entered_renew_grace_period_timestamp_comparator_reverse() throws InterruptedException {
        TreeSet<Session> disconnectSessions = new TreeSet<>(new TokenExpirationHandler.SessionOrderByTokenRenewalTimestamp());

        Session s1 = new Session(null, null);
        Session s2 = new Session(null, null);
        Session s3 = new Session(null, null);

        s3.startTokenRenewal();
        Thread.sleep(200);
        s2.startTokenRenewal();
        Thread.sleep(200);
        s1.startTokenRenewal();
        Thread.sleep(200);

        disconnectSessions.add(s1);
        disconnectSessions.add(s2);
        disconnectSessions.add(s3);

        Iterator<Session> it = disconnectSessions.iterator();

        Session testSession = it.next();
        while(it.hasNext()) {
            Session currentSession = it.next();
            Assert.assertTrue(testSession.getTokenRenewalTimestamp() < currentSession.getTokenRenewalTimestamp());

            testSession = currentSession;
        }
    }

    public static String generateToken(int ttl) {
        return generateToken(ttl, "/s/s", Util.ALL_FIELD);
    }

    public static String generateToken(int ttl, String subject, String field) {
        Map<String, List<String>> permissions = new HashMap<>();
        permissions.put(field, Arrays.asList(subject));

        String jti =  UUID.randomUUID().toString().substring(0, 6);
        String jws = Jwts.builder()
                .setId(jti)
                .claim(Util.PERMISSIONS_FIELD, permissions)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + (ttl * 1000)))
                .signWith(signKey).compact();
        return jws;
    }
}
