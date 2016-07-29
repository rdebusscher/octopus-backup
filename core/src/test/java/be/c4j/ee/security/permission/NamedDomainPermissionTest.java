package be.c4j.ee.security.permission;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class NamedDomainPermissionTest {

    private static final String DOMAIN = "Domain";
    private static final String ACTION1 = "Action1";
    private static final String ACTION2 = "Action2";

    private NamedDomainPermission namedDomainPermission;

    @Test
    public void testCreation() {
        namedDomainPermission = new NamedDomainPermission("test", DOMAIN, ACTION1 + ", " + ACTION2, "*");
        assertThat(namedDomainPermission.getDomain()).isEqualTo(DOMAIN);
        assertThat(namedDomainPermission.getActions()).containsOnly(ACTION1, ACTION2);
        assertThat(namedDomainPermission.getTargets()).containsOnly("*");
    }

    @Test
    public void testCreation_WithWildCard() {
        namedDomainPermission = new NamedDomainPermission("test", DOMAIN + ":" + ACTION1 + ", " + ACTION2 + ":" + "*");
        assertThat(namedDomainPermission.getDomain()).isEqualTo(DOMAIN.toLowerCase());
        assertThat(namedDomainPermission.getActions()).containsOnly(ACTION1.toLowerCase(), ACTION2.toLowerCase());
        assertThat(namedDomainPermission.getTargets()).containsOnly("*");
    }

    @Test
    public void testGetWildcardNotation() {
        namedDomainPermission = new NamedDomainPermission("test", DOMAIN, ACTION1 + ", " + ACTION2, "*");
        assertThat(namedDomainPermission.getWildcardNotation()).isEqualTo(DOMAIN + ":" + ACTION1 + "," + ACTION2 + ":*");

    }

    @Test
    public void testGetWildcardNotation_WithWildCard() {
        namedDomainPermission = new NamedDomainPermission("test", DOMAIN + ":" + ACTION1 + ", " + ACTION2 + ":" + "*");
        String expected = DOMAIN + ":" + ACTION1 + "," + ACTION2 + ":*";
        assertThat(namedDomainPermission.getWildcardNotation()).isEqualTo(expected.toLowerCase());

    }

    @Test
    public void testBypassBugithinSetTargets() {
        NamedDomainPermission permission = new NamedDomainPermission("PERMISSION1", "Permission:1:*");
        assertThat(permission.toString()).isEqualTo("[permission]:[1]:[*]");
    }
}