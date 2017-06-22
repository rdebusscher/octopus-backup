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
package be.c4j.ee.security.interceptor.checks;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.exception.violation.BasicAuthorizationViolation;
import be.c4j.ee.security.interceptor.testclasses.MyAdvancedCheck;
import be.c4j.ee.security.interceptor.testclasses.MyCheck;
import be.c4j.ee.security.interceptor.testclasses.MyCheckInfo;
import be.c4j.ee.security.permission.OctopusPermissionResolver;
import be.c4j.ee.security.realm.OctopusPermissions;
import be.c4j.ee.security.shiro.OctopusSecurityManager;
import be.c4j.test.util.BeanManagerFake;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.deltaspike.security.spi.authorization.EditableAccessDecisionVoterContext;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.subject.Subject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;

import javax.enterprise.util.AnnotationLiteral;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SecurityCheckCustomCheckTest {

    private static final String TEST_PERMISSION = "JUnit:test:*";

    @Mock
    private Subject subjectMock;

    @Mock
    private SecurityViolationInfoProducer infoProducerMock;

    @Mock
    private OctopusConfig configMock;

    @Mock
    private VoterNameFactory nameFactoryMock;

    @Mock
    private OctopusPermissionResolver permissionResolverMock;

    @Mock
    private EditableAccessDecisionVoterContext accessDecisionVoterContextMock;

    @Mock
    private AbstractGenericVoter customVoterMock;

    @Mock
    private OctopusSecurityManager securityManagerMock;

    private BeanManagerFake beanManagerFake;

    @Captor
    private ArgumentCaptor<List> metaDataCaptor;

    @Captor
    private ArgumentCaptor<String> metaDataKeyCaptor;

    @InjectMocks
    private SecurityCheckCustomCheck check;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void performCheck_allowed() {
        when(subjectMock.isAuthenticated()).thenReturn(true);

        when(nameFactoryMock.generateCustomCheckBeanName(anyString())).thenReturn("customVoter");

        beanManagerFake.registerBean("customVoter", customVoterMock);

        SecurityUtils.setSecurityManager(securityManagerMock);

        beanManagerFake.endRegistration();

        Permission permission = new WildcardPermission(TEST_PERMISSION);

        when(permissionResolverMock.resolvePermission(TEST_PERMISSION)).thenReturn(permission);

        Collection<Permission> permissions = new ArrayList<Permission>();
        permissions.add(new WildcardPermission(TEST_PERMISSION));
        permissions.add(new WildcardPermission("JUnit:*:*"));
        when(securityManagerMock.getPermissions(subjectMock, permission)).thenReturn(permissions);

        SecurityCheckInfo checkInfo = check.performCheck(subjectMock, accessDecisionVoterContextMock, new MyCheckLiteral(TEST_PERMISSION, MyCheckInfo.BASIC));
        assertThat(checkInfo).isNotNull();
        assertThat(checkInfo.isAccessAllowed()).isTrue();

        verify(accessDecisionVoterContextMock).addMetaData(metaDataKeyCaptor.capture(), metaDataCaptor.capture());

        assertThat(metaDataKeyCaptor.getValue()).isEqualTo(Permission.class.getName());
        assertThat(metaDataCaptor.getValue()).isEqualTo(permissions);
    }

    @Test
    public void performCheck_NotAllowed() {
        when(subjectMock.isAuthenticated()).thenReturn(true);

        when(nameFactoryMock.generateCustomCheckBeanName(anyString())).thenReturn("customVoter");

        beanManagerFake.registerBean("customVoter", customVoterMock);

        Set<SecurityViolation> violations = new HashSet<SecurityViolation>();
        violations.add(new BasicAuthorizationViolation("JUnit", "null"));
        when(customVoterMock.checkPermission(accessDecisionVoterContextMock)).thenReturn(violations);

        SecurityUtils.setSecurityManager(securityManagerMock);

        beanManagerFake.endRegistration();

        Permission permission = new WildcardPermission(TEST_PERMISSION);

        when(permissionResolverMock.resolvePermission(TEST_PERMISSION)).thenReturn(permission);

        Collection<Permission> permissions = new ArrayList<Permission>();
        permissions.add(new WildcardPermission(TEST_PERMISSION));
        permissions.add(new WildcardPermission("JUnit:*:*"));
        when(securityManagerMock.getPermissions(subjectMock, permission)).thenReturn(permissions);

        SecurityCheckInfo checkInfo = check.performCheck(subjectMock, accessDecisionVoterContextMock, new MyCheckLiteral(TEST_PERMISSION, MyCheckInfo.BASIC));
        assertThat(checkInfo).isNotNull();
        assertThat(checkInfo.isAccessAllowed()).isFalse();

        verify(accessDecisionVoterContextMock).addMetaData(metaDataKeyCaptor.capture(), metaDataCaptor.capture());

        assertThat(metaDataKeyCaptor.getValue()).isEqualTo(Permission.class.getName());
        assertThat(metaDataCaptor.getValue()).isEqualTo(permissions);
    }

    @Test
    public void performCheck_AnnotationAdvancedFlag() {
        when(subjectMock.isAuthenticated()).thenReturn(true);

        when(nameFactoryMock.generateCustomCheckBeanName(anyString())).thenReturn("customVoter");

        beanManagerFake.registerBean("customVoter", customVoterMock);
        when(customVoterMock.checkPermission(accessDecisionVoterContextMock)).thenReturn(new HashSet<SecurityViolation>());

        SecurityUtils.setSecurityManager(securityManagerMock);


        beanManagerFake.endRegistration();

        SecurityCheckInfo checkInfo = check.performCheck(subjectMock, accessDecisionVoterContextMock, new MyAdvancedCheckLiteral());
        assertThat(checkInfo).isNotNull();
        assertThat(checkInfo.isAccessAllowed()).isTrue();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void performCheck_noVoter() {
        when(subjectMock.isAuthenticated()).thenReturn(true);

        when(nameFactoryMock.generateCustomCheckBeanName(anyString())).thenReturn("customVoter");

        SecurityUtils.setSecurityManager(securityManagerMock);

        beanManagerFake.endRegistration();

        Permission permission = new WildcardPermission(TEST_PERMISSION);

        try {
            check.performCheck(subjectMock, accessDecisionVoterContextMock, new MyCheckLiteral(TEST_PERMISSION, MyCheckInfo.BASIC));
        } finally {
            Mockito.verifyNoMoreInteractions(accessDecisionVoterContextMock);
            Mockito.verifyNoMoreInteractions(securityManagerMock);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void performCheck_multiplePermissionValue() {
        when(subjectMock.isAuthenticated()).thenReturn(true);

        when(nameFactoryMock.generateCustomCheckBeanName(anyString())).thenReturn("customVoter");
        beanManagerFake.registerBean("customVoter", customVoterMock);

        SecurityUtils.setSecurityManager(securityManagerMock);

        beanManagerFake.endRegistration();

        Permission permission = new WildcardPermission(TEST_PERMISSION);

        try {
            check.performCheck(subjectMock, accessDecisionVoterContextMock, new OctopusPermissionsLiteral());
        } finally {

            Mockito.verifyNoMoreInteractions(permissionResolverMock);
            Mockito.verifyNoMoreInteractions(accessDecisionVoterContextMock);
            Mockito.verifyNoMoreInteractions(securityManagerMock);
        }
    }

    @Test
    public void performCheck_notAuthenticated() {
        // No beanManagerFake.endregistration
        // If we try to access it -> Exception.
        when(subjectMock.isAuthenticated()).thenReturn(false);

        SecurityCheckInfo checkInfo = check.performCheck(subjectMock, accessDecisionVoterContextMock, new MyCheckLiteral("JUnit:test:*", MyCheckInfo.BASIC));
        assertThat(checkInfo).isNotNull();
        assertThat(checkInfo.isAccessAllowed()).isFalse();

    }

    public class MyCheckLiteral extends AnnotationLiteral<MyCheck> implements MyCheck {
        private static final long serialVersionUID = -8623640277155878656L;

        private String value;
        private MyCheckInfo info;

        public MyCheckLiteral(String value, MyCheckInfo info) {
            this.value = value;
            this.info = info;
        }

        @Override
        public String value() {
            return value;
        }

        @Override
        public MyCheckInfo info() {
            return info;
        }
    }

    public class OctopusPermissionsLiteral extends AnnotationLiteral<OctopusPermissions> implements OctopusPermissions {

        @Override
        public String[] value() {
            return new String[]{"value1", "value2"};
        }
    }

    public class MyAdvancedCheckLiteral extends AnnotationLiteral<MyAdvancedCheck> implements MyAdvancedCheck {
        private static final long serialVersionUID = -8623640277155878657L;


        @Override
        public boolean advanced() {
            return true;
        }
    }

}