/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.c4j.ee.security.permission;

import be.c4j.ee.security.model.UserPrincipal;
import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;
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
    public void testBypassBugWithinSetTargets() {
        NamedDomainPermission permission = new NamedDomainPermission("PERMISSION1", "Permission:1:*");
        assertThat(permission.toString()).isEqualTo("permission:1:*");
    }
}