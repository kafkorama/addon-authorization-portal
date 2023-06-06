package com.migratorydata.authorization.common.token;

import java.util.List;
import java.util.Map;

import static com.migratorydata.authorization.common.config.Util.*;

public class Permissions {
    private final SubjectPermission permissions = new SubjectPermission("");

    /*
    Here is an example of the payload of a JWT token:
    {
    "permissions": {
        "sub": [
          "/demo/notification"
        ],
        "pub": [
          "/sensor/temp"
        ],
        "all": [
          "/server/status",
          "/sensors/*"
        ]
      }
    }
    */
    public Permissions(Map<String, List<String>> permissionClaims) throws Exception {
        for (Map.Entry<String, List<String>> entry : permissionClaims.entrySet()) {
            for (String subject : entry.getValue()) {
                Permission permission = Permission.getPermission(entry.getKey());
                if (isSubjectValid(subject) && permission != Permission.NONE) {
                    putPermission(subject, permission);
                } else {
                    throw new Exception("Invalid syntax for subject " + subject + ", or permission " + entry.getKey());
                }
            }
        }
    }

    private void putPermission(String subject, Permission permission) {
        permissions.setPermission(subject, permission);
    }

    public Permission getPermission(String subject) {
        return permissions.getPermission(subject);
    }

    public enum Permission {
        NONE("none"), SUB("sub"), PUB("pub"), ALL("all");

        private String code;

        Permission(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }

        public static Permission getPermission(String code) {
            Permission permission = NONE;
            if (PUB.getCode().equals(code)) {
                permission = PUB;
            } else if (SUB.getCode().equals(code)) {
                permission = SUB;
            } else if (ALL.getCode().equals(code)) {
                permission = ALL;
            } 
            return permission;
        }
    }
}
