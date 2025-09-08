package com.migratorydata.authorization.token;

import com.migratorydata.extensions.authorization.v2.client.StatusNotification;
import io.jsonwebtoken.*;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.migratorydata.authorization.AuthorizationHandler.*;

/* The payload of a JWT token of Kafkorama Portal looks like:
    {
        "jti": "265c38",              // generic - JWT ID
        "permissions": {              // permissions of the API/APP endpoints
            "sub": [                  // sub
              "/demo/notification"
            ],
            "pub": [                  // pub
              "/sensor/temp"
            ],
            "all": [                  // sub and pub
              "/server/status",
              "/sensors/*"
            ]
        },
        "secret_id": "e967c7",        // the ID of the JWT signing key defined in Kafkorama Portal
        "iat": 1756126132,            // generic - time (epoch in seconds) when the JWT token was generated
        "exp": 1787662132             // generic - time (epoch in seconds) when the JWT token expires
    }
 */
public class Token {
    public static final String PERMISSIONS_FIELD = "permissions";
    public static final String SUB_FIELD = "sub";
    public static final String PUB_FIELD = "pub";
    public static final String ALL_FIELD = "all";
    public static final String SIGNING_KEY_ID_FIELD = "secret_id";

    private final String token;

    private Jws<Claims> jwsClaims = null;
    private Permissions permissions = null;

    public Token(String token) {
        this.token = token;
    }

    public StatusNotification parseToken(JwtParser jwtParser) {
        StatusNotification tokenStatus = TOKEN_VALID;
        try {
            jwsClaims = jwtParser.parseClaimsJws(token);
            permissions = new Permissions((Map<String, List<String>>) jwsClaims.getBody().get(PERMISSIONS_FIELD));
        } catch (MalformedJwtException e) {
            e.printStackTrace();
            tokenStatus = TOKEN_INVALID;
        } catch (JwtException e) {
            e.printStackTrace();
            tokenStatus = TOKEN_EXPIRED;
        } catch (Exception e) {
            e.printStackTrace();
            tokenStatus = TOKEN_INVALID;
        }
        return tokenStatus;
    }

    /**
     * Returns the `jti` field of the JWT token.
     * @return the JWT ID of the token
     */
    public String getId() {
        return jwsClaims.getBody().getId();
    }

    /**
     * Returns the `exp` field of the JWT token.
     * @return the time (epoch in seconds) when the JWT token expires
     */
    public Date getExpirationTime() {
        return jwsClaims.getBody().getExpiration();
    }

    public boolean authorizeSubscribe(String topic) {
        Permissions.PermissionType permission = permissions.getPermission(topic);
        if (permission != null && (permission == Permissions.PermissionType.SUB || permission == Permissions.PermissionType.ALL)) {
            return true;
        }
        return false;
    }

    public boolean authorizePublish(String topic) {
        Permissions.PermissionType permission = permissions.getPermission(topic);
        if ((permission == Permissions.PermissionType.PUB || permission == Permissions.PermissionType.ALL)) {
            return true;
        }
        return false;
    }
}
