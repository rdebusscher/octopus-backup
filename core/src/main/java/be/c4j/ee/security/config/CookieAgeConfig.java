package be.c4j.ee.security.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CookieAgeConfig {

    private static final Pattern CONFIG_PATTERN = Pattern.compile("(\\d+)(h|d)");

    public int getCookieAge(String config) {
        int result = -1;
        Matcher matcher = CONFIG_PATTERN.matcher(config);
        if (!matcher.matches()) {
            throw new OctopusConfigurationException(String.format("Remember-me Cookie age configuration '%s' is not valid, see documentation", config));
        }

        String timeUnit = matcher.group(2);
        if ("h".equals(timeUnit)) {
            result = Integer.valueOf(matcher.group(1)) * 3600;
        }

        if ("d".equals(timeUnit)) {
            result = Integer.valueOf(matcher.group(1)) * 3600  * 24;
        }

        return result;
    }

}
