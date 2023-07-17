package com.migratorydata.authorization.common.token;

import java.util.HashMap;
import java.util.Map;

public class SubjectPermission {

    public static final String SYMBOL_REGEX = "^\\(\\w+\\)$";
    public static final String SYMBOL = "(s)";

    private final Map<String, SubjectPermission> descendants = new HashMap<>();
    private final String name;

    private SegmentType segmentType;
    private Permissions.Permission permission;

    public SubjectPermission(String name) {
        this(name, Permissions.Permission.NONE, SegmentType.NONE);
    }

    private SubjectPermission(String name, Permissions.Permission permission, SegmentType segmentType) {
        this.name = name;
        this.permission = permission;
        this.segmentType = segmentType;
    }

    public void setPermission(String subject, Permissions.Permission permission) {
        addPermission(subject.substring(1), permission, Permissions.Permission.NONE);
    }

    public Permissions.Permission getPermission(String subject) {
        SubjectPermission permission = findPermission(subject.substring(1), Permissions.Permission.NONE);
        if (permission == null) {
            return Permissions.Permission.NONE;
        }
        return permission.permission;
    }

    private SubjectPermission addPermission(String pattern, Permissions.Permission permission, Permissions.Permission wildcardPermission) {
        if (pattern == null) {
            this.update(SegmentType.SUBJECT, permission);
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
            wildcardPermission = this.permission;
        }

        if (segment.equals("*")) {

            SubjectPermission subjectPermission = new SubjectPermission(segment, permission, SegmentType.WILDCARD);
            this.update(SegmentType.WILDCARD, permission);
            descendants.put(segment, subjectPermission);

            this.updateForWildcard(permission);

            return subjectPermission;
        } else if (segment.matches(SYMBOL_REGEX)) {
            segment = SYMBOL;

            SubjectPermission subjectPermission = descendants.get(segment);
            if (subjectPermission == null) {
                if (pattern == null) {
                    subjectPermission = new SubjectPermission(segment, permission, SegmentType.SYMBOL);
                } else {
                    subjectPermission = new SubjectPermission(segment, wildcardPermission, SegmentType.SYMBOL);
                }
                descendants.put(segment, subjectPermission);
            }

            if (pattern != null) {
                return subjectPermission.addPermission(pattern, permission, wildcardPermission);
            }
            return subjectPermission;
        } else {
            SubjectPermission subjectPermission = descendants.get(segment);
            if (subjectPermission == null) {
                if (pattern == null) {
                    subjectPermission = new SubjectPermission(segment, permission, SegmentType.SUBJECT);
                } else {
                    subjectPermission = new SubjectPermission(segment, wildcardPermission, SegmentType.NONE);
                }
                descendants.put(segment, subjectPermission);
            }

            return subjectPermission.addPermission(pattern, permission, wildcardPermission);
        }
    }

    private void updateForWildcard(Permissions.Permission wildCardPermission) {
        for (Map.Entry<String, SubjectPermission> entry : descendants.entrySet()) {
            if (entry.getValue().segmentType != SegmentType.SUBJECT && entry.getValue().permission == Permissions.Permission.NONE) {
                entry.getValue().permission = wildCardPermission;
            }
            entry.getValue().updateForWildcard(wildCardPermission);
        }
    }

    private void update(SegmentType segmentType, Permissions.Permission permission) {
        this.segmentType = segmentType;
        this.permission = permission;
    }

    private SubjectPermission findPermission(String subject, Permissions.Permission wildcardPermission) {

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
            wildcardPermission = this.permission;
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

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(name).append(":").append(permission).append(":").append(segmentType).append("\n");
        for(Map.Entry<String, SubjectPermission> entry : descendants.entrySet()) {
            builder.append(entry.getValue()).append("\n");
        }

        return builder.toString();
    }

    enum SegmentType {
        NONE, WILDCARD, SYMBOL, SUBJECT
    }
}
