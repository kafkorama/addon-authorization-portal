package com.migratorydata.authorization.common.config;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public class Util {

    public static final String APPID_FIELD = "app";
    static final long MICROSECONDS_PER_SECOND = TimeUnit.SECONDS.toMicros(1);
    static final long NANOSECONDS_PER_MICROSECOND = TimeUnit.MICROSECONDS.toNanos(1);

    /**
     * Get the number of nanoseconds past epoch of the given {@link Instant}.
     *
     * @param instant the Java instant value
     * @return the epoch nanoseconds
     */
    public static long toEpochNanos(Instant instant) {
        return TimeUnit.NANOSECONDS.convert(instant.getEpochSecond() * MICROSECONDS_PER_SECOND + instant.getNano() / NANOSECONDS_PER_MICROSECOND, TimeUnit.MICROSECONDS);
    }

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
    public static final String PERMISSIONS_FIELD = "permissions";
    public static final String SUB_FIELD = "sub";
    public static final String PUB_FIELD = "pub";
    public static final String ALL_FIELD = "all";


    private static final Pattern subjectSyntax = Pattern.compile("^\\/([^\\/]+\\/)*([^\\/]+|\\*)$");

    public static boolean isSubjectValid(String subject) {
        String sbj = subject;
        int index = subject.indexOf("/", 1);
        if (index == -1) {
            sbj = subject.substring(1);
            if ("*".equals(sbj)) {
                return true;
            }
        }

        return subjectSyntax.matcher(sbj).matches();
    }
}
