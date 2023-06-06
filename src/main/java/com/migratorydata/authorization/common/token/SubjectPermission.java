package com.migratorydata.authorization.common.token;

import java.util.HashMap;
import java.util.Map;

public class SubjectPermission {

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
        createPermission(subject.substring(1), permission);
    }

    public Permissions.Permission getPermission(String subject) {
        SubjectPermission permission = findPermission(subject.substring(1));
        if (permission == null) {
            return Permissions.Permission.NONE;
        }
        return permission.permission;
    }

    private SubjectPermission createPermission(String subject, Permissions.Permission permission) {
        int i = subject.indexOf("/");
        String segment;
        if (i != -1) {
            segment = subject.substring(0, i);
            subject = subject.substring(i + 1);
        } else {
            segment = subject;
            subject = null;
        }
        if (segment.equals("*") || segment.matches("^\\{\\w+}$")) {
            segment = "*";
            descendants.clear();

            SubjectPermission subjectPermission = new SubjectPermission(getName() + "/" + segment, permission, SegmentType.WILDCARD);
            this.update(SegmentType.WILDCARD, permission);
            descendants.put(segment, subjectPermission);

            return subjectPermission;
        }
        SubjectPermission subjectPermission = descendants.get(segment);
        if (subjectPermission == null) {
            if (this.segmentType == SegmentType.WILDCARD) {
                return this;
            }
            subjectPermission = new SubjectPermission(getName() + "/" + segment);
            descendants.put(segment, subjectPermission);
        }
        if (subject == null) {
            subjectPermission.update(SegmentType.SUBJECT, permission);
            return subjectPermission;
        }
        return subjectPermission.createPermission(subject, permission);
    }

    private void update(SegmentType segmentType, Permissions.Permission permission) {
        this.segmentType = segmentType;
        this.permission = permission;
    }

    private SubjectPermission findPermission(String subject) {
        int i = subject.indexOf("/");
        String segment;
        if (i != -1) {
            segment = subject.substring(0, i);
            subject = subject.substring(i + 1);
        } else {
            segment = subject;
            subject = null;
        }

        SubjectPermission subjectPermission = descendants.get(segment);
        if (subjectPermission == null) {
            return descendants.get("*");
        }
        if (subject == null) {
            if (subjectPermission.segmentType == SegmentType.SUBJECT) {
                return subjectPermission;
            } else {
                return null;
            }

        }
        return subjectPermission.findPermission(subject);
    }

    private String getName() {
        return this.name;
    }

    enum SegmentType {
        NONE, WILDCARD, SUBJECT
    }
}
