package com.migratorydata.authorization.token;

import static com.migratorydata.authorization.token.SubjectPermission.SYMBOL_REGEX;
import org.junit.Assert;
import org.junit.Test;

public class SubjectPermissionTypeTest {

    private SubjectPermission root = new SubjectPermission("");

    @Test
    public void test_root_wildcard() {
        root.setPermission("/*", Permissions.PermissionType.ALL);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_root_normal_subject() {
        root.setPermission("/a", Permissions.PermissionType.ALL);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE);

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE);

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_root_wildcard_root_normal_subject() {
        root.setPermission("/*", Permissions.PermissionType.ALL);
        root.setPermission("/a", Permissions.PermissionType.PUB);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/q");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/w/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_root_wildcard_normal_subject() {
        root.setPermission("/*", Permissions.PermissionType.ALL);
        root.setPermission("/a/b", Permissions.PermissionType.PUB);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/q");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/w/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_normal_subject() {
        root.setPermission("/a/b/c/d", Permissions.PermissionType.ALL);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE);

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE);

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/b/c/d/e");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );
    }

    @Test
    public void test_more_normal_subject_asc() {
        root.setPermission("/a/b/c/d", Permissions.PermissionType.ALL);
        root.setPermission("/a/b", Permissions.PermissionType.SUB);
        root.setPermission("/a", Permissions.PermissionType.PUB);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE);

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

    }

    @Test
    public void test_more_normal_subject_dsc() {
        root.setPermission("/a", Permissions.PermissionType.PUB);
        root.setPermission("/a/b", Permissions.PermissionType.SUB);
        root.setPermission("/a/b/c/d", Permissions.PermissionType.ALL);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE);

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

    }

    @Test
    public void test_wildcard_subject() {
        root.setPermission("/q/w/*", Permissions.PermissionType.PUB);

        Permissions.PermissionType permission = root.getPermission("/q/w");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/q/w/a");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/q/w/c/b");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/q");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );
    }

    @Test
    public void test_normal_subject_on_top_wildcard_subject() {
        root.setPermission("/a/b/c/d", Permissions.PermissionType.ALL);
        root.setPermission("/a/b/*", Permissions.PermissionType.PUB);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_wildcard_subject_on_top_normal_subject() {
        root.setPermission("/a/b/*", Permissions.PermissionType.PUB);
        root.setPermission("/a/b/c/d", Permissions.PermissionType.ALL);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_wildcard_subject_multiple_patterns() {
        root.setPermission("/a/b/c/d", Permissions.PermissionType.ALL);
        root.setPermission("/q/w/*", Permissions.PermissionType.PUB);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/q/w/w/b");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/q/w/a");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );
    }

    @Test
    public void test_wildcard_char_middle() {
        root.setPermission("/a/b/c/d", Permissions.PermissionType.PUB);
        root.setPermission("/a/*/c/d", Permissions.PermissionType.ALL);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );
    }

    @Test
    public void test_symbol_last() {
        root.setPermission("/a/b/<s>", Permissions.PermissionType.PUB);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );
    }

    @Test
    public void test_symbol_middle() {
        root.setPermission("/a/<s>/b", Permissions.PermissionType.PUB);
        root.setPermission("/a/c/b", Permissions.PermissionType.SUB);
        root.setPermission("/a/c/d", Permissions.PermissionType.ALL);


        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/c/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/x/b");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_multiple_symbols_middle() {
        root.setPermission("/a/<s>/b", Permissions.PermissionType.ALL);
        root.setPermission("/a/<s>/<s>/b", Permissions.PermissionType.SUB);
        root.setPermission("/a/c/b", Permissions.PermissionType.PUB);
        root.setPermission("/a/c/d", Permissions.PermissionType.PUB);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/c/b");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/b/d");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/d/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/d/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/d/b/e");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/x/x/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );
    }

    @Test
    public void test_multiple_symbols_middle_wildcard() {
        root.setPermission("/a/<s>/b/<s>", Permissions.PermissionType.PUB);
        root.setPermission("/a/<s>/b", Permissions.PermissionType.ALL);
        root.setPermission("/a/<s>/<s>/b", Permissions.PermissionType.SUB);
        root.setPermission("/a/c/b", Permissions.PermissionType.PUB);
        root.setPermission("/a/c/d", Permissions.PermissionType.PUB);
        root.setPermission("/a/*", Permissions.PermissionType.SUB);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/c/b");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/b/d");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/d/c");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/d/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/x/b/y");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

    }

    @Test
    public void test_multiple_symbols_middle_wildcard_reverse() {
        root.setPermission("/a/*", Permissions.PermissionType.SUB);
        root.setPermission("/a/c/d", Permissions.PermissionType.PUB);
        root.setPermission("/a/c/b", Permissions.PermissionType.PUB);
        root.setPermission("/a/<s>/<s>/b", Permissions.PermissionType.SUB);
        root.setPermission("/a/<s>/b", Permissions.PermissionType.ALL);
        root.setPermission("/a/<s>/b/<s>", Permissions.PermissionType.PUB);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/c/b");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

        permission = root.getPermission("/a/b/d");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/d/c");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/b/d/b");
        Assert.assertTrue(permission == Permissions.PermissionType.SUB );

        permission = root.getPermission("/a/x/b/y");
        Assert.assertTrue(permission == Permissions.PermissionType.PUB );

    }

    @Test
    public void test_combined() {
        root.setPermission("/a/<s>/b/*", Permissions.PermissionType.ALL);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/c/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/x/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/c/b/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_combined_2() {
        root.setPermission("/a/*/b/<s>", Permissions.PermissionType.ALL);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/c/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/x/b");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/c/b/d");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );
    }

    @Test
    public void test_combined_3() {
        root.setPermission("/a/b/<s>/a", Permissions.PermissionType.ALL);

        System.out.println(root);

        Permissions.PermissionType permission = root.getPermission("/a/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/c/b");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );

        permission = root.getPermission("/a/b/c/a");
        Assert.assertTrue(permission == Permissions.PermissionType.ALL );

        permission = root.getPermission("/a/b/c/d");
        Assert.assertTrue(permission == Permissions.PermissionType.NONE );
    }

    @Test
    public void testSymbolRegex() {
        Assert.assertTrue("<a>".matches(SYMBOL_REGEX));
        Assert.assertTrue("<aaa>".matches(SYMBOL_REGEX));
        Assert.assertTrue("<aaa-b_c>".matches(SYMBOL_REGEX));
        Assert.assertTrue("<aaa-b_c?!Z>".matches(SYMBOL_REGEX));
        Assert.assertFalse("<a".matches(SYMBOL_REGEX));
        Assert.assertFalse("a".matches(SYMBOL_REGEX));
        Assert.assertFalse("adbd-e-q_?".matches(SYMBOL_REGEX));
    }
}
