package be.c4j.ee.security.config;

import be.c4j.ee.security.permission.PermissionLookupFixture;
import be.c4j.test.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class VoterNameFactoryTest {

    private VoterNameFactory factory;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        factory = new VoterNameFactory();

    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void testGeneratePermissionBeanName_TyeSafeVersion() {
        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generatePermissionBeanName("PERMISSION1");
        assertThat(beanName).isEqualTo("permission1PermissionVoter");

    }

    @Test
    public void testGeneratePermissionBeanName_TyeSafeVersion_Multiple() {
        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        // Finish preparation
        beanManagerFake.endRegistration();

        String beanName = factory.generatePermissionBeanName("PERMISSION1, PERMISSION2");
        assertThat(beanName).isEqualTo("permission1PermissionVoter, permission2PermissionVoter");

    }

    @Test
    public void testGeneratePermissionBeanName_StringVersion() {

        // The : is in front; so that at other places we can detect it is a name
        String beanName = factory.generatePermissionBeanName("X");
        assertThat(beanName).isEqualTo(":X");

    }

    @Test
    public void testGeneratePermissionBeanName_StringVersion_Multiple() {

        // The : is in front; so that at other places we can detect it is a name
        String beanName = factory.generatePermissionBeanName("X, Y");
        assertThat(beanName).isEqualTo(":X, :Y");

    }

    @Test
    public void testGeneratePermissionBeanName_WildCardVersion() {

        String beanName = factory.generatePermissionBeanName("octopus:test:*");
        assertThat(beanName).isEqualTo("octopus:test:*");

    }

    @Test
    public void testGeneratePermissionBeanName_WildCardVersion_Multiple() {

        String beanName = factory.generatePermissionBeanName("octopus:test:*, octopus:test:second");
        assertThat(beanName).isEqualTo("octopus:test:*, octopus:test:second");

    }

}