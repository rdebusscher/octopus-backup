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
package be.c4j.ee.security.config;

import be.c4j.ee.security.permission.PermissionLookupFixture;
import be.c4j.test.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class VoterNameFactoryTest {

    @Mock
    private OctopusConfig octopusConfigMock;

    private VoterNameFactory factory;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(octopusConfigMock, OctopusConfig.class);

        factory = new VoterNameFactory();

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("PermissionVoter");

    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void generatePermissionBeanName_TyeSafeVersion() {
        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        // Finish preparation
        beanManagerFake.endRegistration();

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("PermissionVoter");

        String beanName = factory.generatePermissionBeanName("PERMISSION1");
        assertThat(beanName).isEqualTo("permission1PermissionVoter");

    }

    @Test
    public void generatePermissionBeanName_AlternativeName() {
        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        // Finish preparation
        beanManagerFake.endRegistration();

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("JUnit");

        String beanName = factory.generatePermissionBeanName("PERMISSION1");
        assertThat(beanName).isEqualTo("permission1JUnit");

    }

    @Test
    public void generateBeanNameForExtension() {

        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generateBeanNameForExtension("PERMISSION1", "SpecialName");
        assertThat(beanName).isEqualTo("permission1SpecialName");

    }

    @Test
    public void generatePermissionBeanName_TyeSafeVersion_Multiple() {
        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        // Finish preparation
        beanManagerFake.endRegistration();

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("PermissionVoter");

        String beanName = factory.generatePermissionBeanName("PERMISSION1, PERMISSION2");
        assertThat(beanName).isEqualTo("permission1PermissionVoter, permission2PermissionVoter");

    }

    @Test
    public void generatePermissionBeanName_StringVersion() {
        // Finish preparation
        beanManagerFake.endRegistration();

        // The : is in front; so that at other places we can detect it is a name
        String beanName = factory.generatePermissionBeanName("X");
        assertThat(beanName).isEqualTo(":X");

    }

    @Test
    public void testGeneratePermissionBeanName_StringVersion_Multiple() {
        // Finish preparation
        beanManagerFake.endRegistration();

        // The : is in front; so that at other places we can detect it is a name
        String beanName = factory.generatePermissionBeanName("X, Y");
        assertThat(beanName).isEqualTo(":X, :Y");

    }

    @Test
    public void generatePermissionBeanName_WildCardVersion() {
        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generatePermissionBeanName("octopus:test:*");
        assertThat(beanName).isEqualTo("octopus:test:*");

    }

    @Test
    public void generatePermissionBeanName_WildCardVersion_Multiple() {
        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generatePermissionBeanName("octopus:test:*, octopus:test:second");
        assertThat(beanName).isEqualTo("octopus:test:*, octopus:test:second");

    }

}