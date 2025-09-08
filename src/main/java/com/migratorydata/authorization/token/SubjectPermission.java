package com.migratorydata.authorization.token;

import java.util.HashMap;
import java.util.Map;

public class SubjectPermission {
    public static final String SYMBOL_REGEX = "^\\(\\w+\\)$";
    public static final String SYMBOL = "(s)";

    private final Map<String, SubjectPermission> descendants = new HashMap<>();

    private final String name;
    private SegmentType segmentType;
    private Permissions.PermissionType permissionType;

    public SubjectPermission(String name) {
        this(name, Permissions.PermissionType.NONE, SegmentType.NONE);
    }

    private SubjectPermission(String name, Permissions.PermissionType permissionType, SegmentType segmentType) {
        this.name = name;
        this.permissionType = permissionType;
        this.segmentType = segmentType;
    }

    public void setPermission(String subject, Permissions.PermissionType permissionType) {
        addPermission(subject.substring(1), permissionType, Permissions.PermissionType.NONE);
    }

    public Permissions.PermissionType getPermission(String subject) {
        SubjectPermission permission = findPermission(subject.substring(1), Permissions.PermissionType.NONE);
        if (permission == null) {
            return Permissions.PermissionType.NONE;
        }
        return permission.permissionType;
    }

    private SubjectPermission addPermission(String pattern, Permissions.PermissionType permissionType, Permissions.PermissionType wildcardPermissionType) {
        if (pattern == null) {
            this.update(SegmentType.SUBJECT, permissionType);
            return this;
        }

        int i = pattern.indexOf("/");
        String segment;
        if (i != -1) {
            segment = pattern.substring(0, i);
            pattern = pattern.substring(i + 1);
        } else {
            segment = pattern;
            pattern = null;
        }

        if (this.segmentType == SegmentType.WILDCARD) {
            wildcardPermissionType = this.permissionType;
        }

        if (segment.equals("*")) {
            SubjectPermission subjectPermission = new SubjectPermission(segment, permissionType, SegmentType.WILDCARD);
            this.update(SegmentType.WILDCARD, permissionType);
            descendants.put(segment, subjectPermission);

            this.updateForWildcard(permissionType);

            return subjectPermission;
        } else if (segment.matches(SYMBOL_REGEX)) {
            segment = SYMBOL;

            SubjectPermission subjectPermission = descendants.get(segment);
            if (subjectPermission == null) {
                if (pattern == null) {
                    subjectPermission = new SubjectPermission(segment, permissionType, SegmentType.SYMBOL);
                } else {
                    subjectPermission = new SubjectPermission(segment, wildcardPermissionType, SegmentType.SYMBOL);
                }
                descendants.put(segment, subjectPermission);
            }

            if (pattern != null) {
                return subjectPermission.addPermission(pattern, permissionType, wildcardPermissionType);
            }
            return subjectPermission;
        } else {
            SubjectPermission subjectPermission = descendants.get(segment);
            if (subjectPermission == null) {
                if (pattern == null) {
                    subjectPermission = new SubjectPermission(segment, permissionType, SegmentType.SUBJECT);
                } else {
                    subjectPermission = new SubjectPermission(segment, wildcardPermissionType, SegmentType.NONE);
                }
                descendants.put(segment, subjectPermission);
            }

            return subjectPermission.addPermission(pattern, permissionType, wildcardPermissionType);
        }
    }

    private SubjectPermission findPermission(String subject, Permissions.PermissionType wildcardPermission) {

        if (subject == null) {
            return this;
        }

        int i = subject.indexOf("/");
        String segment;
        if (i != -1) {
            segment = subject.substring(0, i);
            subject = subject.substring(i + 1);
        } else {
            segment = subject;
            subject = null;
        }

        if (this.segmentType == SegmentType.WILDCARD) {
            wildcardPermission = this.permissionType;
        }

        SubjectPermission subjectPermission = descendants.get(segment);
        if (subjectPermission == null) {
            if (descendants.containsKey(SYMBOL)) {
                return descendants.get(SYMBOL).findPermission(subject, wildcardPermission);
            }
            if (descendants.containsKey("*")) {
                return descendants.get("*");
            }

            return new SubjectPermission(segment, wildcardPermission, SegmentType.WILDCARD);
        }

        return subjectPermission.findPermission(subject, wildcardPermission);
    }

    private void updateForWildcard(Permissions.PermissionType wildCardPermission) {
        for (Map.Entry<String, SubjectPermission> entry : descendants.entrySet()) {
            if (entry.getValue().segmentType != SegmentType.SUBJECT && entry.getValue().permissionType == Permissions.PermissionType.NONE) {
                entry.getValue().permissionType = wildCardPermission;
            }
            entry.getValue().updateForWildcard(wildCardPermission);
        }
    }

    private void update(SegmentType segmentType, Permissions.PermissionType permission) {
        this.segmentType = segmentType;
        this.permissionType = permission;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(name).append(":").append(permissionType).append(":").append(segmentType).append("\n");
        for(Map.Entry<String, SubjectPermission> entry : descendants.entrySet()) {
            builder.append(entry.getValue()).append("\n");
        }
        return builder.toString();
    }

    enum SegmentType {
        NONE, WILDCARD, SYMBOL, SUBJECT
    }
}
