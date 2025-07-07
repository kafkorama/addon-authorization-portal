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

    public static final String PORTAL_URL = "portal.url";
    public static final String PORTAL_PASSWORD = "portal.password";
    public static final String PORTAL_SERVER_ID = "portal.server_id";
    public static final String PORTAL_CLUSTER_ID = "portal.cluster_id";

    public static final String PORTAL_REVOKED_TOKENS_PATH = "internal/revoked_tokens";

    public static final String PORTAL_JWT_SECRET_KEYS_PATH = "internal/jwt_secret_keys";

    private final Properties properties;

    private JwtParser jwtVerifyParser;
    private Key secretKey;

    private Configuration() {
        properties = loadConfiguration();

        if ("hmac".equals(getSignatureType())) {
            secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(getHMACSecretKey()));
            jwtVerifyParser = Jwts.parser().setSigningKey(secretKey).build();
        } else if ("rsa".equals(getSignatureType())){
            try {
                secretKey = getRSAPublicKey();
                jwtVerifyParser = Jwts.parser().setSigningKey(secretKey).build();
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
        Properties props = readPropertiesFile("./addons/authorization-portal/configuration.properties");
        if (props == null) {
            props = readPropertiesFile("/etc/kafkorama-gateway/addons/authorization-portal/configuration.properties");
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

        // access url and password to portal for revoked jwt tokens api.
        if (System.getProperties().containsKey(PORTAL_URL)) {
            props.put(PORTAL_URL, System.getProperty(PORTAL_URL));
        }
        if (System.getProperties().containsKey(PORTAL_PASSWORD)) {
            props.put(PORTAL_PASSWORD, System.getProperty(PORTAL_PASSWORD));
        }
        if (System.getProperties().containsKey(PORTAL_CLUSTER_ID)) {
            props.put(PORTAL_CLUSTER_ID, System.getProperty(PORTAL_CLUSTER_ID));
        }
        if (System.getProperties().containsKey(PORTAL_SERVER_ID)) {
            props.put(PORTAL_SERVER_ID, System.getProperty(PORTAL_SERVER_ID));
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

    public String getWebUrl() {
        return properties.getProperty(PORTAL_URL, "http://127.0.0.1:8080");
    }

    public String getWebGetPassword() {
        return properties.getProperty(PORTAL_PASSWORD, "my-password");
    }

    public String getUrlRevokedTokens() {
        return generatePortalUrl(getWebUrl(), getWebGetPassword(), PORTAL_REVOKED_TOKENS_PATH);
    }

    public String getUrlJwtSecretKeys() {
        return generatePortalUrl(getWebUrl(), getWebGetPassword(), PORTAL_JWT_SECRET_KEYS_PATH) + "/" + getPortalClusterId();
    }

    public String getPortalServerId() {
        return properties.getProperty(PORTAL_SERVER_ID, "default-server-id");
    }

    public String getPortalClusterId() {
        return properties.getProperty(PORTAL_CLUSTER_ID, "default-cluster-id");
    }

    public static String generatePortalUrl(String url, String password, String path) {
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
