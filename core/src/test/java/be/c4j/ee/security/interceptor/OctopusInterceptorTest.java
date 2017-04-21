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
package be.c4j.ee.security.interceptor;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.exception.violation.BasicAuthorizationViolation;
import be.c4j.ee.security.interceptor.checks.*;
import be.c4j.ee.security.interceptor.testclasses.TestCustomVoter;
import be.c4j.ee.security.interceptor.testclasses.TestPermissionCheck;
import be.c4j.ee.security.interceptor.testclasses.TestRoleCheck;
import be.c4j.ee.security.octopus.AnnotationAuthorizationChecker;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.realm.SecurityDataProvider;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import be.c4j.ee.security.twostep.TwoStepConfig;
import be.c4j.test.util.BeanManagerFake;
import be.c4j.test.util.ReflectionUtil;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.interceptor.InvocationContext;
import java.util.Locale;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 *
 */
@Ignore
public class OctopusInterceptorTest {
    protected static final String PERMISSION1 = "PERMISSION1";
    protected static final String PERMISSION2 = "PERMISSION2";
    protected static final String PERMISSION1_WILDCARD = "permission:1:*";
    protected static final String PERMISSION2_WILDCARD = "permission:2:*";
    protected static final Boolean NOT_AUTHENTICATED = Boolean.FALSE;
    protected static final Boolean AUTHENTICATED = Boolean.TRUE;
    protected static final Boolean NO_CUSTOM_ACCESS = Boolean.FALSE;
    protected static final Boolean CUSTOM_ACCESS = Boolean.TRUE;
    protected static final String SHIRO1 = "shiro1:*:*";
    protected static final String ACCOUNT1 = "account1";
    protected static final String NAMED_OCTOPUS = "named:octopus:*";
    protected static final String OCTOPUS = "octopus:*:*";
    protected static final String ROLE1 = "role1";
    protected static final String ROLE2 = "role2";

    protected SecurityCheckOctopusPermission securityCheckOctopusPermission;
    protected SecurityCheckOctopusRole securityCheckOctopusRole;

    protected static final String AUTHORIZATION_PERMISSION = "Authorization:*:*";

    @Mock
    private OctopusConfig octopusConfigMock;

    @Mock
    private TwoStepConfig twoStepConfigConfigMock;

    @Mock
    private SecurityViolationInfoProducer infoProducerMock;

    @Mock
    protected Subject subjectMock;

    @InjectMocks
    protected OctopusInterceptor octopusInterceptor;

    protected VoterNameFactory voterNameFactory;

    protected BeanManagerFake beanManagerFake;

    protected boolean authenticated;
    protected String permission;
    protected boolean customAccess;
    protected String shiroPermission;
    protected String systemAccount;
    protected String role;

    public OctopusInterceptorTest(boolean authenticated, String permission, boolean customAccess, String shiroPermission, String systemAccount, String role) {
        this.authenticated = authenticated;
        this.permission = permission;
        this.customAccess = customAccess;
        this.shiroPermission = shiroPermission;
        this.systemAccount = systemAccount;
        this.role = role;
    }

    @Before
    public void setup() throws IllegalAccessException {
        CallFeedbackCollector.reset();
        initMocks(this);

        ThreadContext.bind(subjectMock);
        if (authenticated) {
            if (systemAccount != null) {
                SystemAccountPrincipal systemAccountPrincipal = new SystemAccountPrincipal(systemAccount);
                when(subjectMock.getPrincipal()).thenReturn(systemAccountPrincipal);
            } else {

                when(subjectMock.getPrincipal()).thenReturn(new Object());

            }
            when(subjectMock.isAuthenticated()).thenReturn(true);
        } else {
            when(subjectMock.isAuthenticated()).thenReturn(false);
        }

        // Define logic at subject level to see if subject has the required permission
        final NamedDomainPermission namedPermission = getNamedDomainPermission(permission);
        final NamedApplicationRole namedRole = getNamedApplicationRole(role);


        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                Object parameter = invocationOnMock.getArguments()[0];
                if (parameter instanceof Permission) {
                    Permission permission = (Permission) parameter;
                    if (namedPermission == null && namedRole == null) {
                        throw new AuthorizationException();
                    }
                    if (namedPermission != null && !namedPermission.implies(permission)) {
                        throw new AuthorizationException();
                    }
                    if (namedRole != null && !namedRole.implies(permission)) {
                        throw new AuthorizationException();
                    }
                    return null;
                }
                throw new IllegalArgumentException();
            }
        }).when(subjectMock).checkPermission((Permission) any());

        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                Object parameter = invocationOnMock.getArguments()[0];
                if (parameter instanceof Permission) {
                    Permission permission = (Permission) parameter;
                    if (namedPermission == null && namedRole == null) {
                        return false;
                    }
                    if (namedPermission != null && !namedPermission.implies(permission)) {
                        return false;
                    }
                    if (namedRole != null && !namedRole.implies(permission)) {
                        return false;
                    }
                    return true;

                }
                throw new IllegalArgumentException();
            }
        }).when(subjectMock).isPermitted((Permission) any());


        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                Object parameter = invocationOnMock.getArguments()[0];
                if (parameter instanceof String) {
                    String permission = (String) parameter;
                    if (!permission.equals(shiroPermission)) {
                        throw new AuthorizationException();
                    } else {
                        return null;
                    }
                }
                if (parameter instanceof String[]) {
                    // as we don't support it in these tests
                    throw new AuthorizationException();
                }
                throw new IllegalArgumentException();
            }
        }).when(subjectMock).checkPermissions((String[]) any());

        // Define the Named permission check class
        when(octopusConfigMock.getNamedPermissionCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return TestPermissionCheck.class;
            }
        });

        // Define the Named permission check class
        when(octopusConfigMock.getNamedRoleCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return TestRoleCheck.class;
            }
        });

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("PermissionVoter");
        when(octopusConfigMock.getRoleVoterSuffix()).thenReturn("RoleVoter");

        // startup mock system for manual/programmatic CDI retrieval
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(octopusConfigMock, OctopusConfig.class);

        // SecurityViolationInfoProducer mock instance assigned to CDI and playback
        beanManagerFake.registerBean(infoProducerMock, SecurityViolationInfoProducer.class);
        when(infoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class), any(NamedDomainPermission.class))).thenReturn("Violation Info");
        when(infoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class))).thenReturn("Violation Info");
        when(infoProducerMock.defineOctopusViolation(any(InvocationContext.class), any(Permission.class))).thenReturn(new BasicAuthorizationViolation("X", "Y"));

        // The custom voter bound to CDI
        TestCustomVoter customVoter = new TestCustomVoter();
        customVoter.setCustomAccess(customAccess);
        beanManagerFake.registerBean(customVoter, TestCustomVoter.class);

        voterNameFactory = new VoterNameFactory();

        SecurityCheckOnlyDuringAuthorization securityCheckOnlyDuringAuthorization = new SecurityCheckOnlyDuringAuthorization();
        ReflectionUtil.injectDependencies(securityCheckOnlyDuringAuthorization, infoProducerMock);

        beanManagerFake.registerBean(securityCheckOnlyDuringAuthorization, SecurityCheck.class);


        SecurityCheckRequiresUser securityCheckRequiresUser = new SecurityCheckRequiresUser();
        ReflectionUtil.injectDependencies(securityCheckRequiresUser, infoProducerMock);

        beanManagerFake.registerBean(securityCheckRequiresUser, SecurityCheck.class);


        SecurityCheckOnlyDuringAuthentication securityCheckOnlyDuringAuthentication = new SecurityCheckOnlyDuringAuthentication();
        ReflectionUtil.injectDependencies(securityCheckOnlyDuringAuthentication, infoProducerMock);

        beanManagerFake.registerBean(securityCheckOnlyDuringAuthentication, SecurityCheck.class);


        SecurityCheckOnlyDuringAuthenticationEvent securityCheckOnlyDuringAuthenticationEvent = new SecurityCheckOnlyDuringAuthenticationEvent();
        ReflectionUtil.injectDependencies(securityCheckOnlyDuringAuthenticationEvent, infoProducerMock);

        beanManagerFake.registerBean(securityCheckOnlyDuringAuthenticationEvent, SecurityCheck.class);


        SecurityCheckNamedPermissionCheck securityCheckNamedPermissionCheck = new SecurityCheckNamedPermissionCheck();
        ReflectionUtil.injectDependencies(securityCheckNamedPermissionCheck, infoProducerMock, octopusConfigMock, voterNameFactory);

        beanManagerFake.registerBean(securityCheckNamedPermissionCheck, SecurityCheck.class);


        SecurityCheckNamedRoleCheck securityCheckNamedRoleCheck = new SecurityCheckNamedRoleCheck();
        ReflectionUtil.injectDependencies(securityCheckNamedRoleCheck, infoProducerMock, octopusConfigMock, voterNameFactory);

        beanManagerFake.registerBean(securityCheckNamedRoleCheck, SecurityCheck.class);


        SecurityCheckCustomVoterCheck securityCheckCustomVoterCheck = new SecurityCheckCustomVoterCheck();
        beanManagerFake.registerBean(securityCheckCustomVoterCheck, SecurityCheck.class);


        SecurityCheckRequiresPermissions securityCheckRequiresPermissions = new SecurityCheckRequiresPermissions();
        ReflectionUtil.injectDependencies(securityCheckRequiresPermissions, infoProducerMock);

        beanManagerFake.registerBean(securityCheckRequiresPermissions, SecurityCheck.class);

        SecurityCheckSystemAccountCheck securityCheckSystemAccountCheck = new SecurityCheckSystemAccountCheck();
        ReflectionUtil.injectDependencies(securityCheckSystemAccountCheck, infoProducerMock);

        beanManagerFake.registerBean(securityCheckSystemAccountCheck, SecurityCheck.class);

        securityCheckOctopusPermission = new SecurityCheckOctopusPermission();
        ReflectionUtil.injectDependencies(securityCheckOctopusPermission, infoProducerMock);

        beanManagerFake.registerBean(securityCheckOctopusPermission, SecurityCheck.class);

        securityCheckOctopusRole = new SecurityCheckOctopusRole();
        ReflectionUtil.injectDependencies(securityCheckOctopusRole, infoProducerMock);

        beanManagerFake.registerBean(securityCheckOctopusRole, SecurityCheck.class);
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    protected void finishCDISetup() throws IllegalAccessException {
        beanManagerFake.endRegistration();

        AnnotationAuthorizationChecker authorizationChecker = new AnnotationAuthorizationChecker();

        AnnotationCheckFactory checkFactory = new AnnotationCheckFactory();
        checkFactory.init();

        ReflectionUtil.injectDependencies(authorizationChecker, checkFactory);


        ReflectionUtil.injectDependencies(octopusInterceptor, authorizationChecker);
    }

    protected NamedDomainPermission getNamedDomainPermission(String permissionName) {
        NamedDomainPermission result = null;
        if (permissionName != null) {

            result = new NamedDomainPermission(permissionName, permissionName.toLowerCase(Locale.ENGLISH), "*", "*");
        }
        return result;
    }

    protected NamedApplicationRole getNamedApplicationRole(String roleName) {
        NamedApplicationRole result = null;
        if (roleName != null) {

            result = new NamedApplicationRole(roleName);
        }
        return result;
    }

    public class TestSecurityDataProvider implements SecurityDataProvider {

        private InvocationContext context;

        public TestSecurityDataProvider(InvocationContext context) {
            this.context = context;
        }

        @Override
        public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
            try {
                octopusInterceptor.interceptShiroSecurity(context);
            } catch (Exception e) {
                if (e instanceof OctopusUnauthorizedException) {
                    throw (OctopusUnauthorizedException) e;
                }
                throw new RuntimeException(e);
            }
            return null;
        }

        @Override
        public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
            try {
                octopusInterceptor.interceptShiroSecurity(context);
            } catch (Exception e) {
                if (e instanceof OctopusUnauthorizedException) {
                    throw (OctopusUnauthorizedException) e;
                }
                throw new RuntimeException(e);
            }
            SimpleAuthorizationInfo result = new SimpleAuthorizationInfo();
            result.addStringPermission(AUTHORIZATION_PERMISSION);
            return result;
        }
    }
}
