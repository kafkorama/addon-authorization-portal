package com.migratorydata.authorization.config;

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
    public static final String CONFIG_FILE_LOCAL = "./addons/authorization-portal/configuration.properties";
    public static final String CONFIG_FILE_SYSTEM = "/etc/kafkorama-gateway/addons/authorization-portal/configuration.properties";

    // Number of seconds before token expiration when a client is notified to renew its JWT token
    public static final String RENEW_TOKEN_BEFORE_SECONDS = "renewTokenBeforeSeconds";
    public static final String RENEW_TOKEN_BEFORE_SECONDS_DEFAULT = "60";

    // There are two methods available for signing/validating JWT tokens:
    // - HMAC using a shared symmetric key, and
    // - RSA using a pair of asymmetric public/private keys
    public static final String SIGNATURE_TYPE = "signature.type"; // available values: "hmac" and "rsa"
    public static final String SIGNATURE_TYPE_DEFAULT = "hmac";
    public static final String SIGNATURE_TYPE_HMAC = "hmac";
    public static final String SIGNATURE_HMAC_SECRET = "signature.hmac.secret";
    public static final String SIGNATURE_HMAC_SECRET_DEFAULT = "He39zDQW7RdkOcxe3L9qvoSQ/ef40BG6Ro4hrHDjE+U=";
    public static final String SIGNATURE_TYPE_RSA = "rsa";
    public static final String SIGNATURE_RSA_PUBLIC_KEY_PATH = "signature.rsa.publicKeyPath"; // this add-on only validate JWT tokens using rsa public key

    // The URL and password of the Kafkorama Portal, required to poll for signing keys and revoked JWT tokens.
    public static final String PORTAL_URL = "com.migratorydata.portal.url";
    public static final String PORTAL_URL_DEFAULT = "http://127.0.0.1:8080";
    public static final String PORTAL_PASSWORD = "com.migratorydata.portal.password";
    public static final String PORTAL_PASSWORD_DEFAULT = "my-password";
    public static final String PORTAL_REVOKED_TOKENS_PATH_DEFAULT = "internal/revoked_tokens";
    public static final String PORTAL_SIGNING_KEYS_PATH_DEFAULT = "internal/secrets";

    private final Properties properties;

    private JwtParser jwtParser;

    private Configuration() {
        properties = loadConfiguration();

        Key jwtSigningKey = null;
        if (SIGNATURE_TYPE_HMAC.equals(getSignatureType())) {
            jwtSigningKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(getHMACSecretKey()));
            jwtParser = Jwts.parser().setSigningKey(jwtSigningKey).build();
        } else if (SIGNATURE_TYPE_RSA.equals(getSignatureType())){
            try {
                jwtSigningKey = getRSAPublicKey();
                jwtParser = Jwts.parser().setSigningKey(jwtSigningKey).build();
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
        Properties props = readPropertiesFile(CONFIG_FILE_LOCAL);
        if (props == null) {
            props = readPropertiesFile(CONFIG_FILE_SYSTEM);
        }
        if (props == null) {
            props = new Properties();
        }
        if (System.getProperties().containsKey(RENEW_TOKEN_BEFORE_SECONDS)) {
            props.put(RENEW_TOKEN_BEFORE_SECONDS, System.getProperty(RENEW_TOKEN_BEFORE_SECONDS, RENEW_TOKEN_BEFORE_SECONDS_DEFAULT));
        }
        if (System.getProperties().containsKey(SIGNATURE_TYPE)) {
            props.put(SIGNATURE_TYPE, System.getProperty(SIGNATURE_TYPE, SIGNATURE_TYPE_DEFAULT));
        }
        if (System.getProperties().containsKey(SIGNATURE_HMAC_SECRET)) {
            props.put(SIGNATURE_HMAC_SECRET, System.getProperty(SIGNATURE_HMAC_SECRET, SIGNATURE_HMAC_SECRET_DEFAULT));
        }
        if (System.getProperties().containsKey(SIGNATURE_RSA_PUBLIC_KEY_PATH)) {
            props.put(SIGNATURE_RSA_PUBLIC_KEY_PATH, System.getProperty(SIGNATURE_RSA_PUBLIC_KEY_PATH));
        }
        if (System.getProperties().containsKey(PORTAL_URL)) {
            props.put(PORTAL_URL, System.getProperty(PORTAL_URL, PORTAL_URL_DEFAULT));
        }
        if (System.getProperties().containsKey(PORTAL_PASSWORD)) {
            props.put(PORTAL_PASSWORD, System.getProperty(PORTAL_PASSWORD, PORTAL_PASSWORD_DEFAULT));
        }

        return props;
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

    public JwtParser getJwtParser() {
        return jwtParser;
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

    public String getPortalUrl() {
        return properties.getProperty(PORTAL_URL, PORTAL_URL_DEFAULT);
    }

    public String getPortalPassword() {
        return properties.getProperty(PORTAL_PASSWORD, PORTAL_PASSWORD_DEFAULT);
    }

    public String getPortalRevokedTokensUrl() {
        return getPortalPathUrl(getPortalUrl(), getPortalPassword(), PORTAL_REVOKED_TOKENS_PATH_DEFAULT);
    }

    public String getPortalSigningKeysUrl() {
        return getPortalPathUrl(getPortalUrl(), getPortalPassword(), PORTAL_SIGNING_KEYS_PATH_DEFAULT);
    }

    private static String getPortalPathUrl(String url, String password, String path) {
        if (url == null || url.isEmpty()) {
            return null;
        }

        if (password == null || password.isEmpty()) {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            sb.append("http://");
        }
        sb.append(url);
        if (!url.endsWith("/")) {
            sb.append("/");
        }
        sb.append(path);
        sb.append("/");
        sb.append(password);
        return sb.toString();
    }
}
