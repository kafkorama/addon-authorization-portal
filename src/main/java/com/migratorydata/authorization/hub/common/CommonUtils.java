package com.migratorydata.authorization.hub.common;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

public class CommonUtils {


    public static String generateRandomUuid(int length) {
        return UUID.randomUUID().toString().substring(0, length);
    }

    public static String generateToken(String apiId, JSONObject permissions, Key secretKey) {
        String jti = CommonUtils.generateRandomUuid(6);
        return Jwts.builder()
                .setId(jti)
                .claim("permissions", permissions.toMap())
                .claim("app", apiId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 31104000000L)) // one year
                .signWith(secretKey).compact();
    }

    public static JSONObject createAllPermissions(String endpoint) {
        JSONObject jsonObject = new JSONObject();
        JSONArray jsonArray = new JSONArray();
        jsonArray.put(endpoint);
        jsonObject.put("all", jsonArray);
        return jsonObject;
    }

    public static String inputStreamToString(InputStream inputStream) {
        final int bufferSize = 8 * 1024;
        byte[] buffer = new byte[bufferSize];
        final StringBuilder builder = new StringBuilder();
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream, bufferSize)) {
            int bytesRead = bufferedInputStream.read(buffer);
            while (bytesRead != -1) {
                builder.append(new String(buffer, 0, bytesRead));
                bytesRead = bufferedInputStream.read(buffer);
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return builder.toString();
    }

    public static JSONArray getRequest(String urlPath) {
        try {
            URL url = new URL(urlPath);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            InputStream inputStream = con.getInputStream();
            JSONArray result = new JSONArray(inputStreamToString(inputStream));
            inputStream.close();
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static JwtParser createJwtParser(String secret) {
        Key secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        JwtParser jwtVerifyParser = Jwts.parser().setSigningKey(secretKey).build();
        return jwtVerifyParser;
    }

    public static Claims getClaimsWithoutVerification(String token) {
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
