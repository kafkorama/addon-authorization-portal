package com.migratorydata.authorization.config;

import org.junit.Assert;
import org.junit.Test;

public class UtilTest {

    @Test
    public void testSubjectSyntax() {
        boolean result = Util.isSubjectValid("/*");
        Assert.assertTrue(result);

        result = Util.isSubjectValid("/a");
        Assert.assertFalse(result);

        result = Util.isSubjectValid("/a/b");
        Assert.assertTrue(result);

        result = Util.isSubjectValid("/a/*/b");
        Assert.assertTrue(result);
    }

}
