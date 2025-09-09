package com.migratorydata.authorization.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.json.JSONArray;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.util.regex.Pattern;

public class Util {

    // SUBJECT_SYNTAX:
    //   ^/                -> must start with '/'
    //   (?:[^/]+/)*       -> zero or more intermediate segments followed by '/'
    //   (?:[^/]+|\*)$      -> must end with a last segment: either a name or '*'
    // Regex note:       non-capturing group (more efficient if no need to match individual segments)
    // Valid examples:   /* , /a/b , /foo/bar/baz
    // Invalid examples: /a , / , // , /a//b , /foo/
    private static final Pattern SUBJECT_SYNTAX = Pattern.compile("^/(?:[^/]+/)*(?:[^/]+|\\*)$");
    public static boolean isSubjectValid(String subject) {
        String sbj = subject;
        int index = subject.indexOf("/", 1);
        // If the subject has only one segment, the only valid case is "/*"
        if (index == -1) {
            sbj = subject.substring(1);
            if ("*".equals(sbj)) {
                return true;
            }
        }
        return SUBJECT_SYNTAX.matcher(sbj).matches();
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
        } catch (IOException e) {
            System.err.println("Failed to read input stream: " + e.getMessage());
        }
        return builder.toString();
    }

    public static JSONArray fetchFromUrl(String urlPath) {
        try {
            URL url = new URL(urlPath);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            InputStream inputStream = con.getInputStream();
            JSONArray result = new JSONArray(inputStreamToString(inputStream));
            inputStream.close();
            return result;
        } catch (Exception e) {
            System.err.println("Failed to fetch JSON from portal's url: " + urlPath + ": " + e.getMessage());
        }
        return null;
    }

    public static JwtParser createJwtParser(String signingKey) {
        Key secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey));
        JwtParser jwtParser = Jwts.parser().setSigningKey(secret).build();
        return jwtParser;
    }

    public static Claims getClaimsWithoutVerification(String token) {
        final Claims[] jwtClaims = {null};
        SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
            Claims claims;
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                // Examine header and claims
                jwtClaims[0] = claims;
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
        return jwtClaims[0];
    }
}
