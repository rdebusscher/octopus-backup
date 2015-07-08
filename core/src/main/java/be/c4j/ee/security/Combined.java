package be.c4j.ee.security;

/**
 *
 */
public enum Combined {
    AND, OR;

    public static Combined findFor(String value) {
        Combined result = Combined.AND;

        if (value != null && "OR".equalsIgnoreCase(value.trim())) {
            result = Combined.OR;
        }

        return result;
    }
}
