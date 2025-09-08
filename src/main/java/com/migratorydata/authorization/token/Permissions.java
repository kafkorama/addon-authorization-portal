package com.migratorydata.authorization.token;

import com.migratorydata.authorization.config.Util;

import java.util.List;
import java.util.Map;

public class Permissions {
    private final SubjectPermission permissions = new SubjectPermission("");

    /* The `permissions` field should have the following format:
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
        }
    */
    public Permissions(Map<String, List<String>> permissionClaims) throws Exception {
        for (Map.Entry<String, List<String>> entry : permissionClaims.entrySet()) {
            for (String subject : entry.getValue()) {
                PermissionType permissionType = PermissionType.fromCode(entry.getKey());
                if (Util.isSubjectValid(subject) && permissionType != PermissionType.NONE) {
                    setPermission(subject, permissionType);
                } else {
                    throw new Exception("Invalid syntax for subject " + subject + ", or permission " + entry.getKey());
                }
            }
        }
    }

    private void setPermission(String subject, PermissionType permissionType) {
        permissions.setPermission(subject, permissionType);
    }

    public PermissionType getPermission(String subject) {
        return permissions.getPermission(subject);
    }

    public enum PermissionType {
        NONE("none"), SUB("sub"), PUB("pub"), ALL("all");

        private String code;

        PermissionType(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }

        public static PermissionType fromCode(String code) {
            PermissionType permissionType = NONE;
            if (PUB.getCode().equals(code)) {
                permissionType = PUB;
            } else if (SUB.getCode().equals(code)) {
                permissionType = SUB;
            } else if (ALL.getCode().equals(code)) {
                permissionType = ALL;
            } 
            return permissionType;
        }
    }
}
