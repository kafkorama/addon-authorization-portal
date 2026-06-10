package com.migratorydata.authorization.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Configuration {
    public static final String CONFIG_FILE_LOCAL = "./addons/authorization-portal/configuration.properties";
    public static final String CONFIG_FILE_SYSTEM = "/etc/migratorydata/addons/authorization-portal/configuration.properties";

    // Number of seconds before token expiration when a client is notified to renew its JWT token
    public static final String RENEW_TOKEN_BEFORE_SECONDS = "renewTokenBeforeSeconds";
    public static final String RENEW_TOKEN_BEFORE_SECONDS_DEFAULT = "60";

    public static final String PORTAL_REQUEST_INTERVAL_SECONDS = "portalRequestIntervalSeconds";
    public static final String PORTAL_REQUEST_INTERVAL_SECONDS_DEFAULT = "10";

    // The URL and password of the Kafkorama Portal, required to poll for signing keys and revoked JWT tokens.
    public static final String PORTAL_URL = "com.migratorydata.portal.url";
    public static final String PORTAL_URL_DEFAULT = "http://127.0.0.1:8080";

    public static final String PORTAL_PASSWORD = "com.migratorydata.portal.password";
    public static final String PORTAL_PASSWORD_DEFAULT = "my-password";
    
    public static final String PORTAL_REVOKED_TOKENS_PATH_DEFAULT = "api/v1/gateway/revoked_tokens";
    public static final String PORTAL_SIGNING_KEYS_PATH_DEFAULT = "api/v1/gateway/sign_keys";

    private final Properties properties;

    private Configuration() {
        properties = loadConfiguration();
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
        if (System.getProperties().containsKey(PORTAL_URL)) {
            props.put(PORTAL_URL, System.getProperty(PORTAL_URL, PORTAL_URL_DEFAULT));
        }
        if (System.getProperties().containsKey(PORTAL_PASSWORD)) {
            props.put(PORTAL_PASSWORD, System.getProperty(PORTAL_PASSWORD, PORTAL_PASSWORD_DEFAULT));
        }
        if (System.getProperties().containsKey(PORTAL_REQUEST_INTERVAL_SECONDS)) {
            props.put(PORTAL_REQUEST_INTERVAL_SECONDS, System.getProperty(PORTAL_REQUEST_INTERVAL_SECONDS, PORTAL_REQUEST_INTERVAL_SECONDS_DEFAULT));
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

    public String getPortalUrl() {
        return properties.getProperty(PORTAL_URL, PORTAL_URL_DEFAULT);
    }

    public String getPortalApiKey() {
        return properties.getProperty(PORTAL_PASSWORD, PORTAL_PASSWORD_DEFAULT);
    }

    public String getPortalRevokedTokensUrl() {
        return getPortalPathUrl(getPortalUrl(), PORTAL_REVOKED_TOKENS_PATH_DEFAULT);
    }

    public String getPortalSigningKeysUrl() {
        return getPortalPathUrl(getPortalUrl(), PORTAL_SIGNING_KEYS_PATH_DEFAULT);
    }

    public int getPortalRequestIntervalSeconds() {
        return Integer.parseInt(properties.getProperty(PORTAL_REQUEST_INTERVAL_SECONDS, PORTAL_REQUEST_INTERVAL_SECONDS_DEFAULT));
    }

    private static String getPortalPathUrl(String url, String path) {
        if (url == null || url.isEmpty()) {
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
        return sb.toString();
    }
}
