package be.c4j.ee.security.systemaccount;

/**
 *
 */
public class SystemAccountPrincipal {

    private String identifier;

    public SystemAccountPrincipal(String identifier) {
        this.identifier = identifier;
    }

    public String getIdentifier() {
        return identifier;
    }
}
