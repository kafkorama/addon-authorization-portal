package com.migratorydata.authorization.token;

import io.jsonwebtoken.*;
import org.junit.Test;

import java.security.Key;

public class ParseWithoutSecretTest {

    @Test
    public void parse() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIzYTZiZjUiLCJwZXJtaXNzaW9ucyI6eyJzdWIiOlsiL21pZ3JhdG9yeWRhdGEvZGVtby9zdG9ja3Mvc3ltYm9scyJdfSwiYXBwIjoiMDQyZjcyOWItNyIsInNlY3JldF9pZCI6ImY2MmJjMyIsImlhdCI6MTc1MTgxNzIzNCwiZXhwIjoxNzgzMzUzMjM0fQ.m3UTPWwOOgOmT5HAoeyyRiAHSJdqJ2Cjr14sAkZ5U7U";

        try {
            Claims claims = parseJwtWithoutSignatureVerification(token);

            // Access the JWT claims
            System.out.println("Subject: " + claims.get(Token.SIGNING_KEY_ID_FIELD));
            System.out.println("Issuer: " + claims.getIssuer());
            System.out.println("Expiration: " + claims.getExpiration());

            // Access specific claim
            String username = claims.get("username", String.class);
            System.out.println("Username: " + username);

        } catch (Exception e) {
            e.printStackTrace();
        }

//        Jwt<Header, Claims> result = Jwts.parser().build().parseClaimsJws("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIzYTZiZjUiLCJwZXJtaXNzaW9ucyI6eyJzdWIiOlsiL21pZ3JhdG9yeWRhdGEvZGVtby9zdG9ja3Mvc3ltYm9scyJdfSwiYXBwIjoiMDQyZjcyOWItNyIsInNlY3JldF9pZCI6ImY2MmJjMyIsImlhdCI6MTc1MTgxNzIzNCwiZXhwIjoxNzgzMzUzMjM0fQ.m3UTPWwOOgOmT5HAoeyyRiAHSJdqJ2Cjr14sAkZ5U7U");
//        System.out.println("Header: " + result.getHeader());
//        System.out.println("Claims: " + result.getBody());
//        System.out.println("JTI: " + result.getBody().getId());
    }

    public static Claims parseJwtWithoutSignatureVerification(String token) {
        final Claims[] claims_ = {null};
        SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
            Claims claims;
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                // Examine header and claims
                claims_[0] = claims;
                return null; // will throw exception, can be caught in caller
            }
        };

        try {
            return Jwts.parser()
                    .setSigningKeyResolver(signingKeyResolver)
                    .build()
                    .parseClaimsJwt(token)
                    .getPayload();
        } catch (Exception e) {
            // no signing key on client. We trust that this JWT came from the server and has been verified there
        }
        return claims_[0];
    }
}
