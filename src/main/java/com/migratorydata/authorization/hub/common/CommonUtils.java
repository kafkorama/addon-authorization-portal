package com.migratorydata.authorization.hub.common;

import io.jsonwebtoken.Jwts;
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
}
