package com.migratorydata.authorization.common.config;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

public class Configuration {
    public static final String RENEW_TOKEN_BEFORE_SECONDS = "renewTokenBeforeSeconds";
    public static final String SIGNATURE_TYPE = "signature.type";
    public static final String SIGNATURE_HMAC_SECRET = "signature.hmac.secret";
    public static final String SIGNATURE_RSA_PUBLIC_KEY_PATH = "signature.rsa.publicKeyPath";

    private final Properties properties;

    private JwtParser jwtVerifyParser;
    private Key secretKey;

    private Configuration() {
        properties = loadConfiguration();

        if ("hmac".equals(getSignatureType())) {
            secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(getHMACSecretKey()));
            jwtVerifyParser = Jwts.parserBuilder().setSigningKey(secretKey).build();
        } else if ("rsa".equals(getSignatureType())){
            try {
                secretKey = getRSAPublicKey();
                jwtVerifyParser = Jwts.parserBuilder().setSigningKey(secretKey).build();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.err.println("Invalid signature type, check the parameter 'signature.type'");
            System.exit(98);
        }
    }

    private final static Configuration config = new Configuration();

    public static Configuration getConfiguration() {
        return config;
    }

    private static Properties loadConfiguration() {
        Properties props = readPropertiesFile("./addons/authorization-hub/configuration.properties");
        if (props == null) {
            props = readPropertiesFile("/etc/migratorydata/addons/authorization-hub/configuration.properties");
        }
        if (props == null) {
            props = new Properties();
        }
        if (System.getProperties().containsKey(RENEW_TOKEN_BEFORE_SECONDS)) {
            props.put(RENEW_TOKEN_BEFORE_SECONDS, System.getProperty(RENEW_TOKEN_BEFORE_SECONDS, "60"));
        }
        if (System.getProperties().containsKey(SIGNATURE_TYPE)) {
            props.put(SIGNATURE_TYPE, System.getProperty(SIGNATURE_TYPE, "hmac"));
        }
        if (System.getProperties().containsKey(SIGNATURE_HMAC_SECRET)) {
            props.put(SIGNATURE_HMAC_SECRET, System.getProperty(SIGNATURE_HMAC_SECRET, "He39zDQW7RdkOcxe3L9qvoSQ/ef40BG6Ro4hrHDjE+U="));
        }
        if (System.getProperties().containsKey(SIGNATURE_RSA_PUBLIC_KEY_PATH)) {
            props.put(SIGNATURE_RSA_PUBLIC_KEY_PATH, System.getProperty(SIGNATURE_RSA_PUBLIC_KEY_PATH));
        }

        if (System.getProperties().containsKey("cluster.internal.servers")) {
            props.put("cluster.internal.servers", System.getProperty("cluster.internal.servers"));
        }
        if (System.getProperties().containsKey("admin.api_segment")) {
            props.put("admin.api_segment", System.getProperty("admin.api_segment"));
        }
        if (System.getProperties().containsKey("admin.user_segment")) {
            props.put("admin.user_segment", System.getProperty("admin.user_segment"));
        }
        if (System.getProperties().containsKey("web.url")) {
            props.put("web.url", System.getProperty("web.url"));
        }
        if (System.getProperties().containsKey("web.password")) {
            props.put("web.password", System.getProperty("web.password"));
        }

        return props;
    }

    public String getClusterInternalServers() {
        return properties.getProperty("cluster.internal.servers");
    }

    public String getApiSegment() {
        return properties.getProperty("admin.api_segment");
    }

    public String getAdminUserSegment() {
        return properties.getProperty("admin.user_segment");
    }

    public String getClusterServerId() {
        if (System.getProperty("com.migratorydata.extensions.authorization.index") != null) {
            return System.getProperty("com.migratorydata.extensions.authorization.index");
        } else {
            return "1";
        }
    }

    private static Properties readPropertiesFile(String fileName) {
        Properties props = new Properties();
        try (InputStream input = new FileInputStream(fileName)){
            props.load(input);
        } catch (IOException e) {
            return null;
        }
        return props;
    }

    public int getMillisBeforeRenewal() {
        return Integer.parseInt(properties.getProperty(RENEW_TOKEN_BEFORE_SECONDS)) * 1000;
    }

    public String getSignatureType() {
        return properties.getProperty(SIGNATURE_TYPE);
    }

    public String getHMACSecretKey() {
        return properties.getProperty(SIGNATURE_HMAC_SECRET);
    }

    public JwtParser getJwtVerifyParser() {
        return jwtVerifyParser;
    }

    public Key getSecretKey() {
        return secretKey;
    }

    public Key getRSAPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String key = new String(Files.readAllBytes(new File(properties.getProperty(SIGNATURE_RSA_PUBLIC_KEY_PATH)).toPath()), Charset.defaultCharset());

        String publicKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\r", "")
                .replaceAll("\n", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public String getSubjectStats() {
        return "/" + getAdminUserSegment() + "/" + getApiSegment() + "/stats";
    }

    public String getWebUrl() {
        return properties.getProperty("web.url", "http://127.0.0.1:8080");
    }

    public String getWebGetPassword() {
        return properties.getProperty("web.password", "my-password");
    }

    public String getUrlRevokedTokens() {
        return getWebUrl() + "/internal/revoked_tokens/" + getWebGetPassword();
    }

    public String getUrlApiLimits() {
        return getWebUrl() + "/internal/api_limits/" + getWebGetPassword();
    }
}
