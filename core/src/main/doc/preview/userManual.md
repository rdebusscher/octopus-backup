Octopus Framework
=================

<span id="author" class="author">C4J - Rudy De Busscher (www.c4j.be)
&lt;rudy.debusscher@c4j.be&gt;</span>  
<span id="revnumber">version 0.9.6.4,</span> <span
id="revdate">28/12/2016</span>

Table of Contents

-   [Release notes](#_release_notes)
    -   [0.9.6.4](#_0_9_6_4)
    -   [0.9.6.3](#_0_9_6_3)
    -   [0.9.6.2](#_0_9_6_2)
    -   [0.9.6.1](#_0_9_6_1)
    -   [0.9.6](#_0_9_6)
    -   [0.9.5](#_0_9_5)
-   [Introduction](#_introduction)
    -   [What is Octopus?](#_what_is_octopus)
-   [Concepts](#_concepts)
    -   [Authentication](#_authentication)
    -   [Authorization](#_authorization)
    -   [Permission](#_permission)
    -   [Domain permission](#_domain_permission)
    -   [Named (domain) permission](#_named_domain_permission)
-   [Features](#_features)
-   [Compatibility](#_compatibility)
-   [Setup](#_setup)
    -   [Add library](#_add_library)
    -   [Non Maven users](#_non_maven_users)
    -   [URL patterns protection](#_url_patterns_protection)
    -   [Login form](#_login_form)
    -   [Named Permissions or/and named
        Roles](#_named_permissions_or_and_named_roles)
    -   [Secure EJB methods](#_secure_ejb_methods)
    -   [Securing JSF components](#_securing_jsf_components)
-   [Setup details](#_setup_details)
    -   [SecurityDataProvider](#_securitydataprovider)
    -   [Authentication](#_authentication_2)
    -   [Authorization](#_authorization_2)
    -   [Authorize URLs](#_authorize_urls)
-   [Exceptions](#_exceptions)
-   [Configuration](#_configuration)
    -   [Configuration properties](#_configuration_properties)
-   [Limits](#_limits)
-   [Securing JAX-RS endpoints](#_securing_jax_rs_endpoints)
-   [Authentication methods](#_authentication_methods)
    -   [Hashed passwords](#_hashed_passwords)
    -   [LDAP integration](#_ldap_integration)
    -   [OAuth2 integration](#_oauth2_integration)
    -   [Authorization with JWT (JSON Web
        Tokens)](#_authorization_with_jwt_json_web_tokens)
    -   [Additional checks on JWT](#_additional_checks_on_jwt)

Release notes
-------------

### 0.9.6.4

1.  Additional CDI bean which allows to add entries for the userInfo map
    of UserPrincipal (SSO client module)

2.  @CheckResult interceptor for verifying permission based on method
    result.

3.  Support for Keycloak as authentication provider.

4.  none filter to block all access to the URL pattern

5.  Some fixes (Exception handling) related to OAuth2

### 0.9.6.3

1.  Support for authentication based on JWT tokens on the header of
    HTTPRequest.

2.  Support for DynamicColumn of PrimeFaces DataTable.

3.  For REST calls, authentication info is never stored also when
    session is available.

### 0.9.6.2

1.  Support for the CSRF token of Google OAuth2 (state parameter).

2.  You can register a custom Shiro filter to some or all URL
    programmatic.

3.  Support for GitHub and Linked OAuth2.

4.  Support for multiple OAuth2 providers within the same application.

Breaking changes

1.  The Token class from Scribe dependency changed to a new package.
    Possibly you have used it in LoginAuthenticationTokenProvider or
    some integration test using OAuth2User.

### 0.9.6.1

1.  permissionListener tag to change JSF Attributes based on security
    requirements.

2.  Configurable logout URL.

3.  Support for CAS SSO server.

4.  BASE64 encoded hashed password support (HEX already supported).

### 0.9.6

1.  New module structure to allow multiple OAuth2 providers.

2.  Easier support for external password validations like LDAP.

3.  Propagation of security information to asynchronous started
    process. (@Asynchronous)

4.  Possibility to define Octopus configuration outside of WAR.

5.  Possibility to define additional shiro.ini files.

6.  Using system accounts (process related and not user related), mainly
    for background processes.

7.  Security Annotations rework (not completely backwards compatible)

8.  Auditing access.

9.  Named permission and role filter where only one of the
    permissions/roles need to be satisfied. (instead of all)

Breaking changes

1.  Security annotations on method level overrides those on class level.

2.  Test module received a different artifact

        <groupId>be.c4j.ee.security.octopus</groupId>
        <artifactId>fakeLogin</artifactId>

3.  Authentication modules (oracle and OAuth2Google) received a
    different artifact

        <groupId>be.c4j.ee.security.octopus.authentication</groupId>

### 0.9.5

1.  Module restructering to support Java EE 6 and Java EE 7 servers.

2.  Plugin mechanism to allow different authentication plugins.

3.  Using Oracle database credentials is now an authentication plugin.

4.  Support for OAuth2 providers as authentication. Google+ only for the
    moment.

5.  Support for JAX-RS controllers.

6.  Test module so that OAuth2 provider is not needed during
    development.

7.  Apache CODI replaced by DeltaSpike

8.  Apache MyFaces Extensions Validator (ExtVal) is replaced by Jerry.

Breaking changes

1.  Parameter of
    be.c4j.ee.security.realm.SecurityDataProvider.getAuthenticationInfo()
    is now **AuthenticationToken** and no longer
    *UsernamePasswordToken*.

Introduction
------------

### What is Octopus?

Octopus is a Permission-based security framework for Java EE, which is
able to secure URL’s, EJB and CDI method calls and JSF components with
the same code. It emphasises the Type safety approach by supporting
named permissions defined by enum constants and deeply integrating it
with the CDI mechanism.

The basis of the Octopus framework can be found in 2 blog posts.

The first one is written by balusc, [Apache Shiro, is it ready for Java
EE
6?](http://balusc.blogspot.nl/2013/01/apache-shiro-is-it-ready-for-java-ee-6.html)
about the possibilities of using **Apache Shiro** with JSF 2. This text
convinced me to use the Apache Shiro framework as a base for the Octopus
Framework. Especially the permission based nature of it was very
important.

The second blog was written by Rudy De Busscher (www.c4j.be), [JSF
Security](http://jsfcorner.blogspot.be/2011/03/jsf-security.html) where
the possibility of securing JSF components with the use of the security
code available in the **Apache MyFaces Extension CDI** (or CODI) is
described.

Based on the information in those 2 sources, combined with CDI based
configuration and type safe definitions of Named permissions with enums,
Octopus was born.

The framework concentrates on using the authentication and authorization
information, not retrieving this information from any source. Therefor
it integrates with a wide range of systems where the information can be
retrieved from like a Database, LDAP and Token based systems as there
are OAuth2 providers (Google, LinkedIn, …​), CAS Server, SAML identity
providers, Keycloak, etc…​

Concepts
--------

This chapter gives an explanation of the concepts which are used
throughout this manual and the software.

### Authentication

Authentication is the process of verifying the credentials the user has
entered to make sure that the user of our application is who he is.
Well, we can never be sure, but the classic approach is that we verify
the user name and password submitted by the user with the values we have
stored somewhere.

### Authorization

Authorization is then in a second step, to shield some parts of the
application from certain users because they are not allowed to see the
information or execute the actions which are foreseen in that area.

### Permission

A **Permission** represents the ability to perform an action or access
to a resource. A Permission is the most granular, or atomic, unit in a
system’s security policy.

### Domain permission

This concept is taken from Apache Shiro. In case of a domain permission,
you enlarge the concept of having a permission. The permission is
divided in 3 parts, the functional area it is assigned to, called the
domain, and also the action and the target of the permission. In our
example, we can define all the permissions related to the functional
area department as having the *domain* **department**. And we can
imagine that we have *actions* like read, create, list and so on. And in
the case we have a very fine grained authorization policy, we can define
that some of those actions are only allowed for a certain department.
For example the department where the employee is working in. The
*target* could then be the value own. Other actions, like list the name
of the departments, should probably allowed by every one. And then we
can specify here the wildcard \*.

The wildcard can be very handy when we need to define a person which has
all the permissions for the domain. Then we can specify the \* for the
value of *actions*.

So from now on we will indicate the domain permissions in the following
format: domain:actions:target, for example department:list:\*

Other features of Apache Shiro related to the domain permission are also
available in the framework. See ??? for some more examples.

### Named (domain) permission

The named permission which is used by the Octopus framework, can be seen
as a kind of simplification. Instead of referring to the 3 parts of the
domain permission, we give it a name. With DEPARTMENT\_READ we could
refer to the permission department:list:\*. This name can then be used
as some kind of *variable name* and we can use it to refer to the domain
permission in a type safe way.

Features
--------

This is the list with the most important features of Octopus

1.  Permission based framework for Java EE (6 and 7).

2.  Secures URL, JSF components and CDI and EJB method calls.

3.  Very flexible, can be easily integrated within your application

4.  Highly configurable using a single property file.

5.  Tightly integrated with CDI.

6.  Type-safe definition of permissions.

7.  Declarative declaration of JSF security (with tags, not using
    rendered attribute).

8.  Support for salted hashed passwords and remember me functionality.

9.  Custom voter can be created for more complex security requirements.

10. Pluggable authentication modules.

11. Support for OAuth2 providers.

12. Support for CAS Server.

13. Support for Keycloak server.

14. Securing JAX-RS Controller.

15. Single sign on principles for the the OAuth2 application.

16. Provides an offline fake provider for OAuth2.

Compatibility
-------------

This is the list of (Application) servers which are tested at this
moment

Java EE 6

1.  Glassfish 3.1.2

2.  TomEE 1.6/1.7

3.  Weblogic 12.1c (Octopus v0.9.4)

Java EE 7

1.  Glassfish 4 / Payara

2.  Wildfly 8/9

List of application servers which will be supported before we reach the
1.0 version

Java EE 6

1.  Weblogic 12.1c

2.  Websphere (Liberty) 8.5.5.5.

It is possible that it already works or will be working with other
versions as it is based on standards.

Setup
-----

This chapter describes the minimal steps you need to do to use the
Octopus framework in your application.

### Add library

Add the octopus artifact to your project dependencies for your
application server(EE6 or EE7). The jsf named artifact is needed when
you use JSF as front end. The steps for using secured JAX-RS controllers
are described in the section *[Securing JAX-RS
endpoints](#REST-section)*.

        <dependency>
            <groupId>be.c4j.ee.security.octopus</groupId>
            <artifactId>javaee7-jsf</artifactId>
            <version>0.9.6.4</version>
        </dependency>

The Octopus artifacts are available in the C4J OS maven repository. You
have to add the following repository definition to your pom.xml file.

        <repository>
            <id>nexus_C4J</id>
            <url>http://nexus-osc4j.rhcloud.com/content/groups/public/</url>
        </repository>

The Octopus library has a few transient dependencies which are imported
automatically (like Jerry). But it also depends on DeltaSpike, which is
not included by default (so that you can define yourself what version of
DeltaSpike you want to use in your application without the risk of
having a dependency conflict). You need the Core and the security
modules.

        <dependency>
            <groupId>org.apache.deltaspike.core</groupId>
            <artifactId>deltaspike-core-api</artifactId>
            <version>1.2.0</version>
            <scope>compile</scope>
        </dependency>

        <dependency>
            <groupId>org.apache.deltaspike.core</groupId>
            <artifactId>deltaspike-core-impl</artifactId>
            <version>1.2.0</version>
            <scope>runtime</scope>
        </dependency>

        <dependency>
            <groupId>org.apache.deltaspike.modules</groupId>
            <artifactId>deltaspike-security-module-api</artifactId>
            <version>1.2.0</version>
            <scope>compile</scope>
        </dependency>

        <dependency>
            <groupId>org.apache.deltaspike.modules</groupId>
            <artifactId>deltaspike-security-module-impl</artifactId>
            <version>1.2.0</version>
            <scope>runtime</scope>
        </dependency>

### Non Maven users

??? TODO

### URL patterns protection

By just adding the Octopus jar file and his dependencies, your
application no longer deploys. It complains that it is missing a CDI
bean which implements the SecurityDataProvider interface. This bean is
required to supply the authentication and authorization information to
the Octopus framework. See *[configuring
authentication](#authentication)* and *[configuring
authorization](#authorization)* for the details how you can do this.

Another thing you need to do before you can start, is to create the
/WEB-INF/securedURLs.ini file. In this file, you can configure which
URLs need to be protected by authentication. An example is in the
following snippet:

       /pages/** = user

It makes sure that all the pages within the pages directory and
subdirectory can’t be accessed without proper authentication. All other
pages in the root or in other directories can be viewed anonymous.

user is the predefined filter by Octopus/shiro that requires
authentication. Another predefined filter is called anon for anonymous
access. See also ??? how you can define other filters based on named
permissions and named roles.

### Login form

Whenever a user navigates to an URL which needs authentication (and he
isn’t already authenticated) the login form is shown. In the scenario
where Octopus/Shiro itself is responsible for verifying the credentials,
see also *[AuthMethods](#_authentication_methods)*. By default this
login page is the */login.xhtml* JSF page. You can use a regular JSF
page for this purpose and there is no restrictions on layout, structure
or component library which is used.

    <h:form id="login">
        <h:panelGrid columns="2">
            <p:outputLabel for="username" value="Username:"/>
            <p:inputText id="username" value="#{loginBean.username}" required="true"/>

            <p:outputLabel for="password" value="Password:"/>
            <p:password id="password" value="#{loginBean.password}" required="true" feedback="" />

            <h:panelGroup/>
            <p:commandButton value="Login" actionListener="#{loginBean.doLogin}" update="@form" process="@form"/>

        </h:panelGrid>
        <p:messages />
    </h:form>

In the above example, the login page is designed with PrimeFaces.
Basically, there are 3 important things

1.  The user name must be bound to the username attribute of the
    loginBean like in *value="\#{loginBean.username}"*

2.  The password must be bound to the password attribute, like in
    *value="\#{loginBean.password}"*

3.  The actual authentication cen be performed by calling the method
    doLogin() by an actionListener, like the *p:commandButton*

No action attribute is required as the user is redirected to the page he
originally requested.

### Named Permissions or/and named Roles

We are now at the point that the authentication (who is it) works, the
next thing is the authorization we need to provide. As specified in the
features chapter, the named permissions (and named roles) can be defined
by using enumeration constants to make it more type-safe.

As the benefit of Octopus lies in the fact that you can use permissions,
we will discuss only permissions in this section. see ??? (for named
roles)

For the named permissions, we can create an enum java class to define
the the values. An example could be

    public enum DemoPermission implements NamedPermission {
        DEPARTMENT_READ, EMPLOYEE_READ_INFO // and other values
    }

Since enum classes can’t be extended, we can’t define an empty class
within the octopus framework that you can extend. Therefor you need to
specify the java class where you have defined the constants for the
named permission in a configuration file. This configuration file, named
octopusConfig.properties by default but can be other file, must be
located in the class root (If you are using Maven, you can place it in
the src/main/resources directory)

    namedPermission.class = be.c4j.demo.security.permission.DemoPermission
    namedPermissionCheck.class = be.c4j.demo.security.permission.DemoPermissionCheck

In the above example of the configuration file, you see also that we
have defined a class which can be used to annotate methods in order to
verify if the user has the required permission to execute the method.
the *namedPermissionCheck* class must be an annotation which accepts
constants of our defined enum, as shown below.

    @Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
    @Retention(RetentionPolicy.RUNTIME)
    public @interface DemoPermissionCheck {
        DemoPermission[] value();
    }

#### Mapping named permissions to domain permissions of Apache Shiro

Since Apache Shiro works with domain permissions and the verification of
the fact that the user has the appropriate rights is performed by Shiro,
we need to supply some mapping between the domain permission and the
named permission of Octopus which are the enum constants.

The PermissionLookup class is designed to do this and an instance of it
can be created by the following code.

        @ApplicationScoped
        @Produces
        public PermissionLookup<DemoPermission> buildLookup() {

            List<NamedDomainPermission> allPermissions = permissionService.getAllPermissions();
            return new PermissionLookup<DemoPermission>(allPermissions, DemoPermission.class);
        }

The constructor takes a list of named permissions and the enum class
which contains the type safe variants. Octopus is using this class
whenever it needs to supply a domain permission to Apache Shiro and the
user has used the enum constant.

### Secure EJB methods

Since EJB methods are the gate to your data, it is advisable that you
put security on all your methods to make sure that your data is
protected and that only those persons who have the required permissions
can perform the actions you assigned them.

Octopus is designed to put security on all EJB methods by simply putting
following snippet in the ejb-jar.xml file (placed in the WEB-INF
directory).

        <interceptors>
            <interceptor>
                <interceptor-class>be.c4j.ee.security.interceptor.OctopusInterceptor</interceptor-class>
            </interceptor>
        </interceptors>
        <assembly-descriptor>
            <interceptor-binding>
                <ejb-name>*</ejb-name>
                <interceptor-class>be.c4j.ee.security.interceptor.OctopusInterceptor</interceptor-class>
            </interceptor-binding>
        </assembly-descriptor>

By putting this into the file, any EJB method call will now fail with
the exception:

    Caused by: be.c4j.ee.security.exception.OctopusUnauthorizedException: No Authorization requirements available

Now you can start adding some annotations which defines the required
permissions to execute the EJB method or all methods of the EJB class.
In the chapter ??? there is an extensive listing of all the
possibilities but this are a few common ones:

1.  @PermitAll, for those cases where also anonymous access is required
    as for instance the methods which reads user information (like
    password) and permissions for the user.

2.  @RequiresUser, if it is enough that the user is authenticated. So
    when no specific permission is required.

3.  @DemoPermissionCheck(DemoPermission.DEPARTMENT\_CREATE), as an
    example of the use of the custom annotation to impose your named
    permission. The name of the annotation is of course free to choose
    and is supplied to Octopus in the *octopusConfiguration.properties*
    file (see also above)

### Securing JSF components

The third type of artifacts where you can impose security on, are the
JSF components. By using a renderer interceptor mechanism (borrowed from
Apache MyFaces Extensions Validation framework), Octopus is able to
disable the rendering of components in declarative way.

The next example shows how you can secure a PrimeFaces button so that
only users with the **DEPARTMENT\_CREATE** permission can see it.

       <p:button value="Create" outcome="/pages/departmentCreate.xhtml">
           <sec:securedComponent permission="DEPARTMENT_CREATE"/>
       </p:button>

So you don’t need to fiddle with the rendered attribute to achieve the
desired effect. You can add a tag inside the component, any component
not only PrimeFaces, to secure the parent. Internally the rendered
attribute is used, so the button is also not available on the screen in
any hidden form to reduce the risks.

Setup details
-------------

### SecurityDataProvider

This chapter describes how you can supply the authentication and
authorization information to Octopus.

The framework is built around the principal that the developer is
responsible for retrieving the information in the correct backed system
(like a database or LDAP system) but that there is no code present in
the framework to do this.

#### Interface

The interface SecurityDataProvider contains 2 methods which are called
by the Octopus framework when information is required.

    public interface SecurityDataProvider {

        AuthenticationInfo getAuthenticationInfo(AuthenticationToken token);

        AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals);
    }

#### getAuthenticationInfo()

This method is called whenever the framework needs to verify some
authentication information.

AuthenticationToken contains information around authentication.
Depending on the authentication method (Login form, tokens, etc) the
actual tye of the parameter may vary. Based on that information, the
developer has 2 possible return values:

1.  **null** means the user name is not known

2.  **AuthenticationInfo instance** means the user name is found and all
    the required information is returned to the Octopus framework.

**UsernamePasswordToken** (subclass of AuthenticationToken) is defined
by Apache Shiro and the getUsername() method returns a *String*
containing the user name specified in the login Form.

For the return Object, you can use the AuthenticationInfoBuilder to
create it for you.

AuthenticationInfoBuilder methods

1.  principalId(Serializable) : Each user must be uniquely identified.
    It will also used by Apache Shiro when the authorization is
    requested.

2.  name(String) : The description for the user, like his full name.
    This can be used to put on it the screen.

3.  userName(String) : The user name if you need this for features like
    re-authentication, auditing and proxy users of Oracle database.
    (Optional)

4.  password(Object) : The password for the user name or the hash when
    hashed passwords are used. See also ??? password mechanism ??? for a
    more complete explanation, like salted hashed passwords. (required
    in certain cases)

5.  externalPasswordCheck() : Defines that we as a developer can’t
    supply the correct password for the username, for example the case
    when we use LDAP.

6.  realmName(String) : name for the realm. Multiple realms are not yet
    supported by Octopus. (optional)

7.  salt(Object) : The salt for the hashed password, see
    \_[hashPassword](#Hashed%20password) (optional)

8.  addUserInfo(Serializable, Serializable) : Add additional information
    about the user that can be used by custom permission voters.
    (optional)

9.  build() : Makes the AuthenticationInfo object.

#### getAuthorizationInfo()

The method is called when Octopus needs to known the permissions for a
certain user/principal. The parameter of the method contains the
principal information for which we need to supply the permission info.

The call to the method principals.getPrimaryPrincipal() returns an
instance of UserPrincipal, an Octopus class which contains for example
the **id** assigned to the user by using the principalId() method from
the *AuthenticationInfoBuilder*. It is the link between the 2 method
calls.

Based on that unique id for the user, the developer needs to return the
authentication info for that user and can make use of the
**AuthorizationInfoBuilder** to do so.

AuthorizationInfoBuilder methods.

1.  addPermission(NamedPermission) : Add the named permission to the
    user. It uses the PermissionLookup instance to translate it to an
    Apache Shiro Domain Permission.

2.  addPermissions(List&lt;NamedPermission&gt;) : Collection version of
    the previous method.

3.  addRole(NamedRole) : Add the named role to the user. It uses the
    RoleLookup instance to translate it to a simple Apache Shore
    permission.

4.  addRoles(List&lt;NamedRole&gt;) : Collection version of the previous
    method.

5.  addPermissionAndRoles(List&lt;? extends Permission&gt;) : Adds a
    list of Apache Shiro Permissions (and thus bypassing Octopus)

6.  build() : Makes the AuthorizationInfo object.

The calls to this getAuthorizationInfo() method is cached and thus only
called once for each user.

### Authentication

This chapter describes the details for integrating the authentication
part into your application.

There are several authentication methods supported in Octopus. We can
categorize them in 3 groups.

1.  Octopus is able to verify if the user supplied credentials (user
    name - password combination) is valid. For example Database and File
    based storages.

2.  Octopus passes the user supplied credentials (user name - password
    combination) to an external source for verification. For example
    LDAP.

3.  Authentication is 'externalised' and application is contacted with a
    token. Examples are Google OAuths, CAS, SAML, Keycloak, Octopus SSO,
    etc.

**Octopus verifies**

In this case, we need to supply the password using the
AuthenticationInfoBuilder to Octopus(Apache shiro). The defaults
matchers (There is also support for hashed password, see
\_[hashPassword](#Hashed%20password)) are able then to verify if the
password matches.

**External validation**

In case we can’t supply Octopus/Apache Shiro the password, but user has
entered credentials in our application, we can ask for an external
authentication and supply a correct *Matcher* which calls the external
validation.

**External authentication**

When the user enters the credentials in an external system and the
verification also happens there, we need special handling for receiving
the token which identifies the authenticated user. In those cases there
is also a special *Matcher*.

**Summary**

In the below table, one can see which of the 3 options applies to your
situation.

<table style="width:99%;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th>Credential entry</th>
<th>Credential verification</th>
<th>Type</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><p>Application</p></td>
<td><p>Application</p></td>
<td><p>Octopus Verifies</p></td>
</tr>
<tr class="even">
<td><p>Application</p></td>
<td><p>External</p></td>
<td><p>External validation</p></td>
</tr>
<tr class="odd">
<td><p>External</p></td>
<td><p>External</p></td>
<td><p>External authentication</p></td>
</tr>
</tbody>
</table>

#### CDI bean for authentication and authorization

As described in the chapter
*[SecurityDataProvider](#SecurityDataProvider)*, there is an interface
defined in Octopus framework which you need to implement to supply the
required security data to the framework.

So you should create a class which implements this interface and
annotate it with @javax.enterprise.context.ApplicationScoped. That way,
an instance of your class will be used by Octopus when it needs
authentication info. The same bean will be used for the authorization
info and will be described in *[Authorization](#authorization)* chapter.

#### Supply authentication info

Some details about the getAuthenticationInfo() method is described in
the section *[getAuthenticationInfo()](#getAuthenticationInfo)*. Since
you have defined a CDI bean, you can inject any kind of service that you
wrote to supply the required information.

When the user specifies an unknown user name, the
getAuthenticationInfo() should return null. Octopus knows then, that it
should show an error. More on the configuration of the error messages,
see ???.

In case your custom service identifies the user name as valid, you
should supply some data.

1.  A unique id which will be used to refer to this user.

2.  A password for the user.

3.  The salt in case of hashed passwords

The password verification is done by the framework itself because the
preferred password mechanism is using some kind of hashed password
mechanism. The code to perform such comparisons is called by the
Framework itself. You just have to specify the hash algorithm (through
configuration), salt (for optimal security) and the hashed password to
be able to perform the comparison. See also ??? password mechanism ??
for some more detail.

The result of the method call is not cached by default, and thus it is
safe to change the authentication info in the external system (like
database or LDAP) without the need to restart the application.

#### Example

In the below code, you find an example of supplying the authentication
info when the external system stores the plain passwords (not
recommended).

    @ApplicationScoped
    public class AppAuthentication implements SecurityDataProvider {

        @Inject
        private YourService service;

        @Override
        public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

            if (token instanceof UsernamePasswordToken) {
               UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken)token;

               MyUser user = service.getUserInfo(usernamePasswordToken.getUsername());
               if (user == null) {
                  return null;
               }
               AuthenticationInfoBuilder authenticationInfoBuilder =
                  new AuthenticationInfoBuilder();
               authenticationInfoBuilder.principalId(user.getId()).
                                       name(user.getName()).
                                       password(user.getPassword());
               return authenticationInfoBuilder.build();
            }
            return null; // Did we use some other authentication method?
        }

        @Override
        public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        }

    }

YourService and MyUser class are project specific and not supplied by
Octopus.

#### Using external checking

When you as developer can’t supply Octopus with the username and
password information, there exists 2 other mechanism. See also
*[AuthMethods](#_authentication_methods)*.

For example when the password is only available in an external system,
like LDAP, you need to use the externalPasswordCheck() method and a
specific Matcher to validate the username and password. An example can
be found ???here???

You can go even further and the complete authentication (checking if the
user specified the correct user name and password combination) can be
handled externally by a third party system using OAuth2, CAS, SAML, etc
…​ Specific extensions are designed to work with these system and
examples are described ???here???

### Authorization

This chapter describes the steps for integrating the authorization part
into your application.

#### CDI bean for authentication and authorization

As described in the chapter
*[SecurityDataProvider](#SecurityDataProvider)*, there is an interface
defined in Octopus framework which you need to implement to supply the
required security data to the framework.

So you should create a class which implements this interface and
annotate it with @javax.enterprise.context.ApplicationScoped. That way,
an instance of your class will be used by Octopus in case it needs some
authorization info. The same bean will be used for the authentication
info and is described in the *[Authentication](#authentication)*
chapter.

#### Supply authorization info

Some details about the getAuthorizationInfo() method is described in the
section *[getAuthorizationInfo()](#getAuthorizationInfo)*. Since you
have defined a CDI bean, you can inject any kind of service that you
wrote to supply the required information.

The authorization info is cached since authorization information is
necessary every time a check is required to see if the user is allowed
to perform some action. So every request the user makes, multiple checks
can be needed and thus caching is indispensable.

The unique id we have supplied during authentication, is supplied as
parameter of the getAuthorizationInfo() method. The following code
snippet can be used to retrieve this unique id out of the **principals**
parameter.

    ((UserPrincipal) principals.getPrimaryPrincipal()).getId()

Using the AuthorizationInfoBuilder instance, we can transfer the
authorization info stored in the external system (like a database or
LDAP) to the Octopus framework.

??? Here we need more info about permissions and roles we can supply ???

#### Example

In the below code, you find an example of supplying the authorization
info when the external system stores the named permissions.

    @ApplicationScoped
    public class AppAuthentication implements SecurityDataProvider {

        @Inject
        private YourService service;

        @Override
        public AuthenticationInfo getAuthenticationInfo(UsernamePasswordToken token) {
        }

        @Override
        public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
            AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
            builder.addPermissions(service.getPermissionsForPrincipal(
                (UserPrincipal) principals.getPrimaryPrincipal())
            );

            return builder.build();
        }

    }

YourService is project specific and not supplied by Octopus.
service.getPermissionsForPrincipal() should return a Collection of
be.c4j.ee.security.permission.NamedPermission items.

### Authorize URLs

Description of the filters we can use in the **securedURL.ini** file.

#### Shiro defined ones

In theory, all Shiro defined filters can be used. But only these seems
us useful.

**anon** Added by default so that any URL whic doesn’t match another
pattern is mapped to this anonymous filter meaning that every access is
allowed.

**user** We need an authenticated use before the URL can be accessed.

**ssl** Access must be through a secure http connection (https)

**noSessionCreation** Handy in the case of URLs used with JAX-RS
endpoints to disable the creation of a HTTP session.

#### Octopus Core

**namedPermission** Specify between brackets the named permission names
which are needed to allow access like namedPermission\[perm1, perm2\]

**np** alias for the *namedPermission* filter

**namedPermission1** When multiple permissions are specified, only one
of them is required to allow access. This in contrary to
*namedPermission* where all permissions are needed.

**np1** alias for *namedPermission1* filter

namedRole Specify between brackets the named roles which are needed to
allow access like namedRole\[role1, role2\]

**nr** alias for the *namedRole* filter

**namedRole1** When multiple roles are specified, only one of them is
required to allow access. This in contrary to *namedRole* where all
roles are needed.

**nr1** alias for *namedRole1* filter

**voter** Specify the named voter wich needs to be used to verify if the
user has access to the URL.

**audit** Filter for auditing access, is used when the configuration
parameter globalAuditActive is set but can also be used on selective URL
patterns.

**none** All access to these URL patterns is prohibited.

#### OAuth2 Google module

**user** is redefined specific for Google OAuth2 functionality.

**GoogleAuthcFilter** Uses the value in the Authorization header as a
bearer token/access token and verifies it with Google.

#### OAuth2 GitHub module

**user** is redefined specific for GitHub OAuth2 functionality.

**GithubAuthcFilter** Uses the value in the Authorization header as a
bearer token/access token and verifies it with Github.

#### OAuth2 LinkedIn module

**user** is redefined specific for LinkedIn OAuth2 functionality.

**LinkedinAuthcFilter** Uses the value in the Authorization header as a
bearer token/access token and verifies it with LinkedIn.

#### CAS module

**user** is redefined specific for CAS functionality.

#### Keycloak module

**user** is redefined specific for Keycloak functionality.

#### JWT module

**jwt** Filter which uses the value of the Authorization header in
combination with an implementation of
**be.c4j.ee.security.credentials.authentication.jwt.jwt.JWTHelper** to
define if the call is allowed.

Exceptions
----------

???

OctopusConfigurationException

IncorrectCredentialsException

UnknownAccountException

Configuration
-------------

This chapter describes all the configuration options of the Octopus
framework.

By default, the octopusConfig.properties file is read on the classpath.
But we can specify another properties file with a JVM system property so
that we can configure the WAR file externally (no need to rebuild the
WAR file between environment)

With the -Doctopus.cfg=&lt;someURL&gt; option, we can specify the
location of an additional properties file which will be read and use for
configuring the system.

### Configuration properties

#### securedURLs.file

default : **/WEB-INF/securedURLs.ini**

The securedURLs.ini file contains the permissions required to access
some URLs. See ?? for the format of the file. The file must always
exists and contain at least one URL entry.

#### namedPermission.class

default : **(none)**

Defines the Enum class which enumerates all permissions. Within the demo
example it is the class
**be.c4j.demo.security.permission.DemoPermission**.

#### namedPermissionCheck.class

default : **(none)**

Defines the annotation which can be used on method and class level to
define the security requirements.

#### namedRole.class

default : **(none)**

Defines the Enum class which enumerates all named roles. It is the role
counterpart of the namedPermission.class configuration option.

#### namedRoleCheck.class

default : **(none)**

Defines the annotations which can be used on method and class level to
define the security requirements.

#### additionalShiroIniFileNames

default : **classpath:shiro\_extra.ini**

Define the file where we can customize shiro directly. This file will be
merged with the config of octopus. Multiple files can be specified by
separating them by a ,.

#### globalAuditActive

default : **false**

When true, each server request will result in a CDI event with payload
OctopusAuditEvent.

#### aliasNameLoginBean (JSF Only)

default : **(none)**

The CDI managed bean which can be used to login and logout the user is
called **loginBean**. With this configuration option you can give it an
additional name so that you can use this configured value in the JSF
pages instead of **loginBean**.

#### loginPage (JSF Only)

default : **/login.xhtml**

The JSF page which will be called when the user access a security
restricted page in your application and isn’t logged in yet. It should
contain the fields and button to allow him to login into your
application.

#### logoutPage (JSF Only)

default : **/**

URL used as redirect after the local session is logged out. When the
value starts with a '/' the URL is relative to the root, otherwise it
should a full address.

#### unauthorizedExceptionPage (JSF Only)

default : **/unauthorized.xhtml**

The JSF page which is called when the user access a security restricted
page and he doesn’t has the required permissions (roles) to access it.

#### allowPostAsSavedRequest (JSF Only)

default : **true**

When user is redirect to the login screen because he is not
authenticated yet, the original URL is stored. So it can be used to
redirect to if the user has supplied valid credentials. However, with
JSF applications, posting to an arbitrary page results in exceptions as
the state of the previous pages is missing.

With this property you can disable the redirect to an URL which uses
POST as HTTP method. A redirect to the welcome page of your application
will be used instead.

#### hashAlgorithmName

default : **(none)**

Name of the MessageDigest algorithm when you use hashed passwords.
examples are Md5 and Sha512.

#### saltLength

default : **0**

Number of bytes used when creating a salt for the hashing of passwords.
0 means that no salt is used.

#### hashEncoding

default : **HEX**

Defines how the hashed passwords are encoded (HEX or BASE64) before they
are compared to the supplied value which should be identically before
access is granted. The value specified in the configuration file is case
insensitive compared with the allowed values.

#### cacheManager.class

default : **org.apache.shiro.cache.MemoryConstrainedCacheManager**

The class responsible for holding/managing the cache of the
authentication and authorization data. The developer can supply a custom
implementation of org.apache.shiro.cache.AbstractCacheManager when the
cache needs different logic.

#### OAuth2.clientId (OAuth2 only)

default : **(none)**

The value used for the clientId configuration value towards your OAuth2
provider.

#### OAuth2.secretId (OAuth2 only)

default : **(none)**

The value used for the secretId configuration value towards your OAuth2
provider.

#### OAuth2.scopes (OAuth2 only)

default : **(none)**

The additional scopes you want to use when the authentication is
performed with the OAuth2 Provider.

#### OAuth2.provider.selectionPage (OAuth2 only)

default : **/login.xhtml**

The page which is shown to the user when multiple OAuth2 providers are
found on the classpath so that the user can choose which provider he
wants to take.

#### keycloak.file (keycloak only)

default : **(none)**

The location of the JSON configuration file for the Keycloak
integration. It can be generated by using the Keycloak Web admin pages.

#### keycloak.scopes (keycloak only)

default : **(none)**

Additional scopes you want to pass to Keycloak. Std OpenIdConnect
feature.

#### keycloak.idpHint (keycloak only)

default : **(none)**

When multiple Social Login providers are configured, hint the user to a
specific one.

#### keycloak.single.logout (keycloak only)

default : **true**

Is Single logout active? When true, the keycloak server is called to end
the SSO session for the user. In turn Keycloak sill contact all
applications which are using the SSO session to terminate their specific
session.

#### SSO.server (Octopus SSO, CAS, SAML, Keycloak)

default : **(none)**

The login URL (or part of it) of the remote authentication page. See the
specific authentication module for correct usage.

#### CAS.protocol (CAS only)

default : **CAS**

The protocol used with the CAS server for exchange of authentication.
Other supported value is SAML.

#### CAS.single.logout (CAS only)

default : **true**

Is Single logout active? When true, after local logout the browser is
redirected to the logout page of CAS resulting in ending the SSO session
and all Local sessions active under that SSO Session.

#### CAS.property.email (CAS only)

default : **email**

The name of the cas attribute containing the email address.

#### jwk.file (JWT and Octopus SSO)

default : **(none)**

Location of the JWK file (with RSA public keys) for the JWT signature
verification. See ???

#### jwt.systemaccounts.only (JWT only)

default : **True**

Are only SystemAccounts allowed when using authentication based on JWT
tokens?

#### jwt.systemaccounts.map (JWT only and Octopus SSO)

Properties file where the system accounts are defined for each api-key.

#### fakeLogin.localhostOnly (fakeLogin only)

default : **true**

When using offline login authentication instead of OAuth2, is this only
allowed on localhost.

#### SSO.application (Octopus SSO only)

default : **(none)**

Future usage when Octopus SSO is fully operational.

#### SSO.application.suffix (Octopus SSO only)

default : **(none)**

Future usage when Octopus SSO is fully operational.

Limits
------

1.  The genericPermissionVoter based automatically created CDI beans for
    the permissions can’t be used in Session and Conversation scoped
    beans.

Securing JAX-RS endpoints
-------------------------

For securing JAX-RS or REST endpoints, we need to add the following
dependencies to the project.

The first one is just to translate an unauthorized exception to return a
401 response with the error message in the body.

        <dependency>
            <groupId>be.c4j.ee.security.octopus</groupId>
            <artifactId>octopus-rest</artifactId>
            <version>0.9.6.4</version>
        </dependency>

In the case we use some token based authentication methods, we need the
corresponding artifact. For example the Google OAuth2 module.

        <dependency>
            <groupId>be.c4j.ee.security.octopus.authentication</groupId>
            <artifactId>octopus-oauth2-google</artifactId>
            <version>0.9.6.4</version>
        </dependency>

The next step we need to do is, to define how the URL endpoints are
protected. Defined in the securedURLs.ini file.

       /data/** = noSessionCreation, GoogleAuthcFilter, userRest

*noSessionCreation* : Defines that Apache Shiro shouldn’t create a HTTP
session. This is logic for a JAX-RS environment as it is typically
stateless.

*GoogleAuthcFilter* : The authentication filter which defines how the
header information is used to determine if the request is valid.

*userRest* : Translates an unauthorized exception into an HTTP response
with status 401.

Authentication methods
----------------------

Different scenarios around authentication are described in the next
sections.

### Hashed passwords

#### Background

<a href="https://crackstation.net/hashing-security.htm" class="uri" class="bare">https://crackstation.net/hashing-security.htm</a>

Hashed passwords with a different value for the salt for each user is
one of the most secure ways of storing password values. Because from the
hashed password, the original value is very hard to retrieve, or
practical impossible with the newer hash algorithms like SHA-512.

#### Setup

There is no additional dependency needed to support hashed passwords.
The Core artifact (included by the JSF artifact) contain all the
required classes.

The parameter hashAlgorithmName defines if the hashed password option is
active.

    hashAlgorithmName=SHA-256

When this parameter is defined in one of the octopusConfig.properties
files, the hashed Password matcher of apache Shiro will be used to
compare the entered and the expected password.

Supported hash algorithms are MD2, MD5, SHA-1, SHA-256, SHA-384 and
SHA-512.

#### Authentication

In the same way we have to pass a 'regular' (non hashed password) to
Octopus/Shiro, we have to do it also in the case of the hashed expected
password. But we also have to supply the salt which is used in
calculating the hash value.

Warning; the next snippet is not a good production example as the hashed
password is calculated for each login!!

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(principalId++).name(token.getPrincipal().toString());

            // Best practice is that each user has his own salt value. So we create a salt here for each checks to simulate that.
            // See also the saltLength parameter for the length of this salt.
            // TODO: Change for production. salt needs to be retrieved together with the hashed password and generated as in this example.
            byte[] salt = saltHashingUtil.nextSalt();

            authenticationInfoBuilder.salt(salt);
            // TODO: Change for production. Here we use username as password. It is the expected hash of the password
            String hashedPassword = saltHashingUtil.hash(usernamePasswordToken.getUsername(), salt);
            authenticationInfoBuilder.password(hashedPassword);

            return authenticationInfoBuilder.build();
        }
        return null;
    }

The above example code generates a hash of the username for a created
salt value. And passes that information to Octopus.

Important to note here is that we not only need to supply the hashed
version of the expected password through the password() method but that
we also have to give the salt (by means of the salt() method which needs
to to be used to be able to calculate the correct hash.

These are the steps followed to check if the correct password is
supplied.

1.  Prepend the salt to the plain password entered by the user

2.  Apply the hash algorithm

3.  Compare this calculated value with the expected hash.

#### Salt generation

In this scenario, it is likely that you would also like to manage the
user from within the application and store the information in for
example a database instance.

In those situations, you need a new salt for each new user and it is
recommended that you also update the salt when the user changes his/her
password. A convenient method for generating a new salt if provided by a
utility class of Octopos.

    byte[] salt = saltHashingUtil.nextSalt();

The length of this value is determined by the configuration parameter
saltLength. And longer salts are safer then short salt values.

#### Other utility methods

Since you also need to store the hash in to a database for example, it
is easier when this value contains only regular characters (like a to Z)
instead of any type of character (byte) which can also be control
characters.

Base64 is a typical conversion which you can use to convert any type of
byte sequence to a 'readable' string in a revertable way. (this is
different from the one way hashing algorithms used above)

For this purpose you can use the org.apache.shiro.codec.Base64 class.

### LDAP integration

#### setup

No additional dependencies are required to support password
authentication against an LDAP server.

However, we need a specific Apache Shiro Matcher that will check the
supplied user name and passwords against an LDAP instance. That matcher
needs to be configured within a shiro\_extra.ini file. (Or specified
within another ini file but then you need to specify that name in the
config)

    [main]
    LDAPMatcher = be.c4j.demo.security.LDAPMatcher
    credentialsMatcher.matcher = $LDAPMatcher

#### SecurityDataProvider.getAuthenticationInfo()

We need to define a login form our self, and the getAuthenticationInfo()
method of the bean implementing the SecurityDataProvider interface will
be called with an instance of UsernamePasswordToken.

However, we are unable to supply the correct password for the user to
Octopus/Shiro but need to pass them to an LDAP instance. So we have an
*external password check* and thus we need the following snippet in the
getAuthenticationInfo() method.

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof UsernamePasswordToken) {

            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            // principalId is used for the authorization
            authenticationInfoBuilder.principalId(usernamePasswordToken.getUsername());

            // username can be handy for auditing purposes
            authenticationInfoBuilder.userName(usernamePasswordToken.getUsername());
            // This means we have to rely on an additional defined CredentialsMatcher
            authenticationInfoBuilder.externalPasswordCheck();

            return authenticationInfoBuilder.build();
        }

        return null;

    }

#### CredentialsMatcher

The matcher can be written using standard Java code (you don’t need an
additional library for accessing LDAP instances). The following example
uses a custom CDI bean to perform the actual verification (code not
shown here).

    public class LDAPMatcher implements CredentialsMatcher, Initializable {

        private LDAPAuthenticator ldapAuthenticator;

        @Override
        public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {

            String name = ldapAuthenticator.isValidAuthentication(token.getPrincipal().toString(), new String((char[]) token.getCredentials()));
            if (name != null && info instanceof ExternalPasswordAuthenticationInfo) {
                ExternalPasswordAuthenticationInfo externalInfo = (ExternalPasswordAuthenticationInfo) info;
                externalInfo.setName(name);
                //externalInfo.addUserInfo("key", serializableValue);
            }
            return name != null;
        }

        @Override
        public void init() throws ShiroException {
            ldapAuthenticator = BeanProvider.getContextualReference(LDAPAuthenticator.class);
        }
    }

The class implements org.apache.shiro.util.Initializable, the Apache
Shiro equivalent of the PostConstruct in Java EE. It allows you to
prepare the instance for all dependencies. Here it uses the **DeltaSpike
BeanProvider** to retrieve the CDI instance.

The ldapAuthenticator returns the name of the authenticated user (if the
credentials are valid)

The AuthenticationInfo class as parameter of doCredentialsMatch()
method, is supplied by Apache Shiro but Octopus makes an extension,
ExternalPasswordAuthenticationInfo when we have an external password
check (as specified by externalPasswordCheck() method of the
AuthenticationInfoBuilder. This extended class allows you to set
additional user info which can be used later on.

        @Inject
        private UserPrincipal principal;

        public void doSomething() {
           principal.getUserInfo("key");
        }

### OAuth2 integration

#### setup

Add the following dependency to your project POM.xml file.

        <dependency>
            <groupId>be.c4j.ee.security.octopus.authentication</groupId>
            <artifactId>octopus-oauth2-google</artifactId>
            <version>0.9.6.4</version>
        </dependency>

The above dependency add the required dependency to have OAuth2
authentication with Google as provider.

But other providers are also supported, this table gives an overview of
the provider, artifactId and name (see further)

<table style="width:99%;">
<colgroup>
<col width="33%" />
<col width="33%" />
<col width="33%" />
</colgroup>
<thead>
<tr class="header">
<th>OAuth2 Provider</th>
<th>artifactId</th>
<th>name</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><p>Google</p></td>
<td><p>octopus-oauth2-google</p></td>
<td><p>Google</p></td>
</tr>
<tr class="even">
<td><p>GitHub</p></td>
<td><p>octopus-oauth2-github</p></td>
<td><p>Github</p></td>
</tr>
<tr class="odd">
<td><p>LinkedIn</p></td>
<td><p>octopus-oauth2-linkedin</p></td>
<td><p>Linkedin</p></td>
</tr>
</tbody>
</table>

And if you like, you can add multiple OAuth2 modules, so that the end
user of your application can choose which provider he wants to use. See
in the configuration, what you need to do in order to make this scenario
work.

#### Configuration

For each OAuth2 provider, we need to specify the clientId and
clientSecret code that we received from the provider. This needs to be
done in the octopusConfig.properties file.

    OAuth2.clientId=??????????.apps.googleusercontent.com
    OAuth2.clientSecret=???????????????

Since the authentication part is done externally, the functionality of
the SecurityDataProvider.getAuthenticationInfo() method is a bit
different.

The type of the parameter token is of a special type, OAuth2User. Your
implementation should check on this type to make sure that the
authentication did go well.

The type has specific getters for certain properties, like id and email,
which are provided by most providers. All the other information which is
collected (see ???) can be retrieved by looking into the *userInfo* map.

A typical implementation of the method looks like this.

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof OAuth2User) {
            OAuth2User user = (OAuth2User) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(user.getId()).name(user.getFullName());
            authenticationInfoBuilder.addUserInfo(user.getUserInfo());

            return authenticationInfoBuilder.build();
        }
        return null;
    }

Of course, you can do additional things here and also limit hwo can
access your application.

In the case where you have build an application which should only be
used by the employees of your company (which are using for example
Google for work and thus have all a Google account) you can verify the
email domain of the logged in user to check if the authenticated user
belongs to your company (OAuth2User.getEmail() ). In the case the user
isn’t allowed access to your app, you can just return *null* as the
result of the getAuthenticationInfo() method.

#### Additional configuration

There are additional configuration options possible.

For example, in the case where you use the Provider not only for the
authentication but also want to use additional services of the provider
(like retrieving the number of repositories of the user from GitHub, the
connections on Google+ or LinkedIn, etc…​) you need to specify
additional scopes during the authentication so that the end user is
aware of what your application will do when they authorize.

The OAuth2 scope defines the type of information your application will
able to read from the provider when to end user approves it. And those
scope names are specific for each provider and thus can’t be
standardized with Octopus or any other framework.

You are able to specify those scopes which needs to be added to the
default one(s) (which Octopus already defines to be able to read basic
information like email address and name of the user) in the
octopusConfiguration.proeprties file.

For example, the next snippet shows the config to be able to read the
Google+ information for the circles of the user.

    OAuth2.scopes=https://www.googleapis.com/auth/plus.circles.read

#### Using multiple providers

You can use multiple OAuth2 providers and let the user select the one
(s)he want to use for the authentication of your application.

The first step is add the different modules to your application as
dependency. Octopus identifies that there are multiple providers on the
classpath and when the end users want to access a protected resource,
Octopus shows the page identified in the configuration parameter
OAuth2.provider.selectionPage so that the end user can make the
selection of the provider (s)he wants to use.

This selection page must be provided by the application developer and
all the available providers can be retrieved from
defaultOauth2ServletInfo.providers EL Expression.
*defaultOauth2ServletInfo* is a CDI bean defined by Octopus which helps
the application developer to deal with multiple OAuth2 providers. Below
is an example of a simple selection screen.

        <ui:repeat value="#{defaultOauth2ServletInfo.providers}" var="_provider">
            <p:commandLink actionListener="#{defaultOauth2ServletInfo.authenticateWith(_provider)}" value="#{_provider}"/>
            <br/>
        </ui:repeat>

The getProviders() method returns a List of String’s of the OAuth2
providers found on the classpath. The names corresponds to the one
listed here ??? The application developer is of course free how the
selection screen is structured and what information is shown to help the
user to select the provider of his choice. The only requirement he has,
is that the method authenticateWith(String) is called so that the
correct provider selection can be stored and the authentication flows
proceeds correctly to the initially requested page.

The last thing we need to do is to specify the correct *clientId* and
*secretId* for the different providers (within the
*octopusConfig.properties* file). In the case you need to specify
multiple values, you need to use the name profix to the OAuth2
configuration parameter so that Octopus can use the correct one
depending on the provider selected by the end user.

    # Google
    Google.OAuth2.clientId=25208181163-ekbphgh4s9k3f78g3j3lfulqcd9p7a1l.apps.googleusercontent.com
    Google.OAuth2.clientSecret=yGKzScuRFm90pR0pNWOedDRx

    # GitHub
    Github.OAuth2.clientId=271f8e3eacb955487e92
    Github.OAuth2.clientSecret=26a3030a10e742e4edf4a0496ee707fdfd18cf4b

    # Linkedin
    Linkedin.OAuth2.clientId=771a48ph3b53xt
    Linkedin.OAuth2.clientSecret=CM5ekYbsZR6y0smD

The above snippet comes from the multiple OAuth2 provider demo
application where we specify the *clientId* and *secretId* fror the 3
providers.

#### Configuration of the OAuth2 provider

This section contains briefly how the OAuth2 authentication on the
provider side can be set up. However, this information and requested
data can change as it is not under the control of Octopus.

##### Google

1.  Go the the [developers
    console](https://console.developers.google.com/) of Google.

2.  Select the *Create new project* option from the drop down of project
    on the menu bar on top of the screen.

3.  Specify a name (only used to identify the project in the console
    later on) and click the *Create* button.

4.  *Select the API manager* menu option on the side bar (can be hidden,
    click on the 'Hamburger' icon - The icon with the 3 horizontal
    lines)

5.  Add and enable the *Google+ API*. Other API’s can be removed for
    Octopus.

6.  Go to the *Credentials* menu and select the *OAuth Client ID* as new
    Credential.

7.  Configure the consent screen (most things are optional).

8.  Select *Web Application* as application type.

9.  Specify the redirect URI
    &lt;hostname&gt;/&lt;root&gt;/oauth2callback and &lt;hostname&gt; as
    *Authorized JavaScript origins*

10. Note down the client-id and client secret values.

###### Multiple accounts

When the user has multiple accounts of Google, there is the possibility
to have a selection screen which account he wants to use every time he
logs on to the application.

He can call the /usingMultipleAccounts URL with the parameter
value=true. The next time Octopus calls the Google OAuth2 provider, an
additional parameter is sent to indicate that Google needs to show the
account selection screen. Also when the user is only logged in with one
account or even has only one account.

You can disable this feature again by calling the servlet with a
value=false which makes sure the cookie is removed.

The developer can customize the screen which is shown when the user
calls the /usingMultipleAccounts URL by implementing the
MultipleAccountContent interface and annotating it with a CDI scope
(preferably ApplicationScoped).

##### Github

1.  Go the Developer application page of
    [Githib](https://github.com/settings/applications) by selecting the
    tab *Developer applciations*.

2.  Click on the *Register new application* button.

3.  Define the application name, Authorization callback URL (as
    &lt;hostname&gt;/&lt;root&gt;/oauth2callback) and the other
    information

4.  Click on the *register application* button and note down the
    client-id and client secret values.

##### LinkedIn

1.  Go to the [application overview
    page](https://www.linkedin.com/developer/apps) of your linked in
    account.

2.  Click on the *Create application* button.

3.  You have to fill in quite some fields. The *Application use* drop
    down can be *Other* if you just use it jsut for the authentication
    step.

4.  We need the scopes *r\_emailaddress* and *r\_basicprofile*

5.  Note down the client-id and client secret values.

### Authorization with JWT (JSON Web Tokens)

#### Use case

When you have some JAX-RS (Rest) endpoints which needs to be called by
other processes within your organization, you need some way to make sure
that you can authorize does calls.

Since the other party is a process, user name and password are too
fragile (insecure) to use. The use of a signed JWT token (with the
Private key of an RSA key) gives us a quit reliable way of establishing
the authentication.

#### Setup for accessing JAX-RS endpoints with Service accounts.

We need the following dependencies in the project setup:

        <dependency>
            <groupId>be.c4j.ee.security.octopus</groupId>
            <artifactId>octopus-rest</artifactId>
            <version>0.9.6.4</version>
        </dependency>

        <dependency>
            <groupId>be.c4j.ee.security.octopus.authentication</groupId>
            <artifactId>jwt</artifactId>
            <version>0.9.6.4</version>
        </dependency>

The *rest* dependency will give us the *userRest* filter so that
authentication exceptions are translated to a 401 response.

The *jwt* dependency has the *jwt* filter that perform the
authentication and populate the security context with the System
account.

For an introduction around JWT, JWK and relates concepts, have a look on
internet and/or this excellent [site](http://jwt.io/introduction/) for
an introduction.

The source repository contains 2 helper programs to create the required
JWT/JWK artefacts for this usage scenario. RSA and EC keys versions of
the programs are available.

/examples/rest/jwt-util module; be.c4j.ee.security.jwt.JWKManagerRSA
/examples/rest/jwt-util module; be.c4j.ee.security.jwt.JWKManagerEC

When you run this program; it prints out 3 artifacts on the console:

x-api-key : This is an unique identification for your third party
Private : a JWK file containing the private and public parts of an RSA
key which can be used to sign the JWT token which they will send to your
Rest endpoint. Public : A JWK file containing the public part of the
same RSA key which octopus will use the verify the signing part of the
JWT token.

You need to give the private JWK file to your third party, the public
part needs to be integrated within your application;

/examples/rest/jwt-util module; be.c4j.ee.security.jwt.JWTTesterRSA
/examples/rest/jwt-util module; be.c4j.ee.security.jwt.JWTTesterEC

An example how you can create a JWT token and read the content from a
token.

Copy the information of the private and public JWK file in the
private.jwk and public.jwk file in the resource folder.

Specify the required configuration options in the
octopusConfig.properties file (src/main/resources)

    jwk.file = demo.jwk
    jwt.systemaccounts.map = systemAccounts.properties

The jwk.file indicates the file with the public key(s) of the RSA key.
For an example, you can also look at the public.jwk file in the
/examples/rest/jwt-util module.

By default, Octopus only allows system accounts and the list of system
accounts which are allowed for each api key is defined in the
systemAccounts.properties file.

    cbeba027-39e1-4c70-a584-77081422e16a=xDataScience

In the above example, we define that only the accounts xDataScience (the
value of the sub claim in the JWT token) is allowed for the api key. See
further for an example of a valid JWT token.

The last configuration step we have to do is to specify the correct
filters for the URL of our REST end point. This is done in the
webapp/WEB-INF/securedURLs.ini file.

    /data/** = noSessionCreation, userRest, jwt

The *userRest* filter converts any authentication exception into an HTTP
status 401.

The *jwt* filter is performing the authentication based on the
HTTPServlet request parameters.

??? We can use the @SystemAccount annotation to grant a certain System
account access to an EJB method.

#### HTTPServlet request requirements for JWT authorization

Each request, JWT is stateless by design, must contain the following
parameters

<table>
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Parameter name</th>
<th>example</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><p>x-api-key</p></td>
<td><p>cbeba027-39e1-4c70-a584-77081422e16a</p></td>
</tr>
<tr class="even">
<td><p>Authorization</p></td>
<td><p>Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6ImNiZWJhMDI3LTM5ZTEtNGM3MC1…​</p></td>
</tr>
</tbody>
</table>

The *Authorization* parameter contains the JWT token, and the general
structure looks like

xxxxx.yyyyy.zzzzz

xxxxx = Header

And should contains the following items

{"alg":"RS512","typ":"JWT","kid":"cbeba027-39e1-4c70-a584-77081422e16a"}

<table>
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>key</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><p>alg</p></td>
<td><p>Signing algorithm</p></td>
</tr>
<tr class="even">
<td><p>typ</p></td>
<td><p>Type of token, Octopus only supports JWT</p></td>
</tr>
<tr class="odd">
<td><p>kid</p></td>
<td><p>Key ID</p></td>
</tr>
</tbody>
</table>

The Key ID must be the same value as the *x-api-key* parameter. The
reason why it is defined outside the token is that it determines which
RSA public Key needs to be used to verify the integrity of the JWT. And
thus it is better that we have that information outside the key (so that
we don’t need to read the content before we can verify it’s integrity.

yyyyy = Payload or Claims

{"exp":1458918709,"sub":"xDataScience","aud":"CVApp","clientAddress":"127.0.0.1","iat":1458918649}

<table>
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>iat</th>
<th>Issued At (timestamp, not used by default by Octopus)</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><p>exp</p></td>
<td><p>Expiration time (timestamp, not used by default by Octopus)</p></td>
</tr>
<tr class="even">
<td><p>sub</p></td>
<td><p>subject (will be the name of the system account)</p></td>
</tr>
<tr class="odd">
<td><p>aud</p></td>
<td><p>Audience (intended for, not used by default by Octopus)</p></td>
</tr>
</tbody>
</table>

In the above example, there is also an example of a custom claim
(clientAddress)

zzzzz = Signature

Octopus uses RSA keys to bne sure that the request for access can only
be originated by 1 third party (the one we have given the private key
used to create the signing part of the JWT)

### Additional checks on JWT

#### Use case

The developer can impose additional checks on the JWT before it is
considered valid.

It can therefor implement the interface
be.c4j.ee.security.credentials.authentication.jwt.CheckJWTClaims.

    public interface CheckJWTClaims {

        void areClaimsValid(HttpServletRequest request, Map<String, Object> headerParams, Map<String, Object> claims);
    ----

    The parameter contains the HTTPServletRequest, header parameters and claims of the JWT. In case, the requirements aren't met for the developer, it can throw an +be.c4j.ee.security.credentials.authentication.jwt.ClaimCredentialsException+. The authentication process will then fail.

    The implementation must be a CDI bean, preferably ApplicationScoped since there is no need to keep state.


    === Keycloak integration

    ==== Use case

    Keycloak is an Access and Identity management server of RedHat. http://www.keycloak.org/[keycloak home]

    It has many features like SSO, Social logins, Central User management and is based on standards like Oauth2, OpenIdConnect en SAML.

    The integration of Octopus with Keycloak is only support using the OpenIdConnect protocol.

    ==== Modules

    There are 3 ways of using it available
    . keycloak-se: The first Java SE module of Octopus which is meant be usable from Command Line application, Swing or JavaFX application.
    . keycloak-rest: To protect JAX-RS endpoints with Access token generated by Keycloak
    . keycloak: The JSF module for Web application.

    ==== Version

    The integration code within Octopus is compiled with the version 2.0.0.Final.  It is possible that it works only with Keycloak instance 2.0+ (and not with 1.x series)

    ==== Keycloak configuration

    You need to perform a few configuration steps within keycloak to be able to integrate it with Octopus (this is nothing specific to Ocotpus but general requirement)

    . If needed, create a specific realm for your application or test.
    . Add a client, keep the client protocol at 'openid-connect'
    . Specify as root URL, <AppRoot>/keycloak/* where <AppRoot> is the root URL for your application like localhost:8080/demo

    All options can be adjusted to your needs, some of them are important in some cases for Octopus

    TBD

    === CAS integration

    ==== setup

    Add the following dependency to your project POM.xml file.

    [source,xml]
    ----
        <dependency>
            <groupId>be.c4j.ee.security.octopus.authentication</groupId>
            <artifactId>cas</artifactId>
            <version>0.9.6.1</version>
        </dependency>
    ----

    Define the following parameters in the _octopusConfig.properties_ file (preferably outside the WAR file so that your WAR file becomes environment neutral)

    ----
    SSO.server=https://<cas-server>/cas
    ----

    Where the we point to the main context of the CAS server installation.

    And that is all what needs to be done to have your application using the CAS server for identity management.

    ==== SecurityDataProvider.getAuthenticationInfo()

    The +getAuthenticationInfo()+ method of the bean implementing the SecurityDataProvider interface will be called with a specific parameter, the +be.c4j.ee.security.credentials.authentication.cas.CasUser+.

    This method should return null if the parameter isn't of the correct type, otherwise we can use the AuthenticationInfoBuilder to build the required information for Octopus.

    [source,java]
    ----
    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof CasUser) {
            CasUser user = (CasUser) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(user.getTicket()).name(user.getName());

            return authenticationInfoBuilder.build();
        }
        return null;
    }
    ----


    ==== Retrieving user attributes

    The CAS server is able to send some additional attributes to your applications. These can be configured within the CAS configuration. See for example following http://jasig.github.io/cas/4.1.x/integration/Attribute-Release.html[documentation page]

    These attributes are available with the CasUser parameter during the +SecurityDataProvider.getAuthenticationInfo()+ method execution. It can be used to retrieve additional information stored about the logged on user or for any other purpose.

    We can make these attributes available in an unmodified format if we pass them to the AuthenticationInfoBuilder instance using the +addUserInfo()+ method. These attributes are then available in the principal as follows

    [source,java]
    ----
        @Inject
        private UserPrincipal principal;

        public void doSomething() {
           principal.getUserInfo("theAttribute");
        }
    ----


    ==== Advanced configuration

    Single logout. ??? TODO refer to general explanation what this is.

    Protocol CAS versus SAML.  ??? TODO


    === Using Oracle Users for authentication

    One of the classic scenarios is that the users which are allowed to access your application, are stored in a database table.

    However, there exists a range of application running on the Oracle database which uses the database users to perform the authentication. With Octopus this is also possible when a stored function is installed on the database (scripts provided in the appendix)

    ==== Setup

    Add the following dependency to your project POM.xml file.

    [source,xml]
    ----
        <dependency>
            <groupId>be.c4j.ee.security.octopus.authentication</groupId>
            <artifactId>octopus-oracle</artifactId>
            <version>0.9.6.1</version>
        </dependency>
    ----

    By adding this dependency, specific configuration options are added and no additional steps are needed.

    ==== Configuration

    As explained in the _<<SecurityDataProvider>>_ chapter, the +getAuthenticationInfo()+ method of the +SecurityDataProvider+ interface is responsible for returning the required data to the Octopus code.
    When we are validating the credentials against the schema users of the Oracle database, we are unable to supply the required password for the user to Octopus/Shiro.

    In the appendix, you can find a PL/SQL function which is able to verify if a username password combination is valid credentials (they can then also be used to logon to Oracle).
    This function is called from the default entityManager defined in your application by a special +CredentialsMatcher+ which is automatically configured.

    ==== Authentication

    Although the check is performed by a special +CredentialMatcher+, the logic isn't executed when we don't indicate that we have a valid user name. So the +getAuthenticationInfo()+ method needs to return an instance of +AuthenticationInfo+.

    The following snippet is minimal required code:

    [source, java]
    ----
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(usernamePasswordToken.getUsername()));

            return authenticationInfoBuilder.build();

        }
        return null;
    }
    ----

    But other methods of +AuthenticationInfoBuilder+ can be used to pass information to Octopus/Shiro.

    ==== Authorization

    For authorization purposes, the +getAuthorizationInfo()+ method is still called and you need to return the permissions the user has.  The *principalId* which is supplied to this method is to user name in uppercase.


    === Local development

    There are various helper classes that can be handy during development.

    ==== Offline OAuth2 support

    In order to completely work offline with OAuth2, you need a fake login handler.

    By adding the following dependency, we add a servlet which is capable of providing some authentication information to Octopus.

    [source,xml]
    ----
        <dependency>
            <groupId>be.c4j.ee.security.octopus</groupId>
            <artifactId>fakeLogin</artifactId>
            <version>0.9.6.4</version>
        </dependency>

    ----

    It is advisable to use this dependency only in development, through a maven profile, because it allows bypassing the OAuth2 authentication which you obviously don't want to be possible in a production system.
    However, there is safety mechanism implemented which allows the fake login only on the localhost URL.

    See the +fakeLogin.localhostOnly+ configuration property if you want to change this.

    The authentication information you like to use when performing an offline authentication, can be specified in a CDI bean (ApplicationScoped) which implements +be.c4j.ee.security.fake.LoginAuthenticationTokenProvider+

    This is an example implementation

    [source,java]
    ----
    @ApplicationScoped
    public class DemoLoginAuthenticationTokenProvider implements LoginAuthenticationTokenProvider {

        @Override
        public AuthenticationToken determineAuthenticationToken(String loginData) {
            return defaultUser();
        }

        private OAuth2User defaultUser() {
            OAuth2User result = new OAuth2User();
            result.setFirstName("_Rudy_");
            result.setLastName("_De Busscher_");

            // These are all required
            result.setFullName("_Rudy De Busscher_");
            result.setId("Fake");
            result.setDomain("c4j.be");
            result.setEmail("rudy.debusscher@c4j.be");
            result.setToken(new Token("Fake", ""));
            return result;
        }
    }
    ----


    == Other features

    Octopus has also some other small features which are handy in certain cases

    === Requested pages auditing

    Since all requests are passed through the Shiro framework to determine if the user is allowed to retrieve the information, we can easily keep track of which user requested a certain page when.

    For that purpose, a CDI event is thrown when the configuration parameter +globalAuditActive+ is set to true. With the onRequest method below, we can then store or log the access of the user.

    [source,java]
    ----
    public void onRequest(@Observes OctopusAuditEvent octopusAuditEvent) {
    }
    ----

    The +OctopusAuditEvent+ class contains following information:
    . String requestURI -> The requested URI by the user
    . Object principal -> The object describing the logged on principle or null if anonymous access. By default, Octopus return an instance of +UserPrincipal+ in the parameter.
    . String remoteAddress -> The remote address (IP address) of the user.

    JSF AJAX calls don't trigger the generation of this event.

    === Additional filters

    Octopus has the possibility to add some custom (Shiro) filters to some or all the URLs programmatic. If you need this feature, you can also use regular Web filters for this purpose, you need to implement the +GlobalFilterConfiguration+ interface and define it as an +ApplicationScoped+ CDI bean.

    [source,java]
    ----
    public interface GlobalFilterConfiguration {

        Map<String, Class<? extends AdviceFilter>> getGlobalFilters();

        List<String> addFiltersTo(String url);
    }
    ----

    The method +getGlobalFilters+ returns the filters we want to add to the configuration of Shiro/Ocotopus. Just as with any other Shiro filter we need the implementing class and the name we give it.

    With the help of the +addFiltersTo+ method we can determine which of the filters defined with the other method, we like to add to a certain URL.



    == Appendix

    ==== Oracle Stored function for OracleCredentialsMatcher

    For an oracle 10g database, create this function in the schema of the user used in the connection pool to the database from the application server (or grant the required executions rights in addition to a public synonym)

    [source]
    ----
    create or replace FUNCTION check_password(
        username IN VARCHAR2,
        password IN VARCHAR2)
      RETURN VARCHAR2
    IS

      raw_key raw(128):= hextoraw('0123456789ABCDEF');

      raw_ip raw(128);
      pwd_hash VARCHAR2(16);

      CURSOR c_user (cp_name IN VARCHAR2)
      IS
        SELECT password FROM sys.user$ WHERE password IS NOT NULL AND name=cp_name;

    PROCEDURE unicode_str(
        userpwd IN VARCHAR2,
        unistr OUT raw)
    IS
      enc_str   VARCHAR2(124):='';
      tot_len   NUMBER;
      curr_char CHAR(1);
      padd_len  NUMBER;
      ch        CHAR(1);
      mod_len   NUMBER;
      debugp    VARCHAR2(256);
    BEGIN
      tot_len:=LENGTH(userpwd);
      FOR i IN 1..tot_len
      LOOP
        curr_char:=SUBSTR(userpwd,i,1);
        enc_str  :=enc_str||chr(0)||curr_char;
      END LOOP;
      mod_len    := mod((tot_len*2),8);
      IF (mod_len = 0) THEN
        padd_len := 0;
      ELSE
        padd_len:=8 - mod_len;
      END IF;
      FOR i IN 1..padd_len
      LOOP
        enc_str:=enc_str||chr(0);
      END LOOP;
      unistr:=utl_raw.cast_to_raw(enc_str);
    END;

    FUNCTION getHash(
        userpwd IN raw)
      RETURN VARCHAR2
    IS
      enc_raw raw(2048);

      raw_key2 raw(128);
      pwd_hash raw(2048);

      hexstr        VARCHAR2(2048);
      LEN           NUMBER;
      password_hash VARCHAR2(16);
    BEGIN
      dbms_obfuscation_toolkit.DESEncrypt(input => userpwd, KEY => raw_key, encrypted_data => enc_raw );
      hexstr  :=rawtohex(enc_raw);
      LEN     :=LENGTH(hexstr);
      raw_key2:=hextoraw(SUBSTR(hexstr,(LEN-16+1),16));
      dbms_obfuscation_toolkit.DESEncrypt(input => userpwd, KEY => raw_key2, encrypted_data => pwd_hash );
      hexstr       :=hextoraw(pwd_hash);
      LEN          :=LENGTH(hexstr);
      password_hash:=SUBSTR(hexstr,(LEN-16+1),16);
      RETURN(password_hash);
    END;
    BEGIN
      OPEN c_user(upper(username));
      FETCH c_user INTO pwd_hash;
      CLOSE c_user;
      unicode_str(upper(username)||upper(password),raw_ip);
      IF( pwd_hash = getHash(raw_ip)) THEN
        RETURN ('Y');
      ELSE
        RETURN ('N');
      END IF;
    END;
    ----

    For an oracle 11g database, this the version of the stored function which you need.

    [source]
    ----
    create or replace FUNCTION CHECK_PASSWORD(
        p_USERNAME IN VARCHAR2 ,
        p_PASSWORD IN VARCHAR2 )
      RETURN VARCHAR2
    AS
      lv_pwd_raw RAW(128);
      lv_enc_raw RAW(2048);
      lv_hash_found VARCHAR2(300);
      CURSOR c_main(cp_user IN VARCHAR2)
      IS
        SELECT SUBSTR(spare4,3,40) hash,
          SUBSTR(spare4,43,20) salt,
          spare4
        FROM sys.user$
        WHERE name=cp_user;
      lv_user c_main%rowtype;
      lv_result VARCHAR2(1);
    BEGIN
      OPEN c_main(upper(p_USERNAME));
      FETCH c_main INTO lv_user;
      CLOSE c_main;
      lv_pwd_raw   := utl_raw.cast_to_raw(p_password)||hextoraw(lv_user.salt);
      lv_enc_raw   := sys.dbms_crypto.hash(lv_pwd_raw, 3);
      lv_hash_found:= utl_raw.cast_to_varchar2(lv_enc_raw);

      IF lv_enc_raw = lv_user.hash THEN
        lv_result  := 'Y';
      ELSE
        lv_result := 'N';
      END IF;
      RETURN lv_result;
    END CHECK_PASSWORD;
    ----

Version 0.9.6.4  
Last updated 2016-12-28 20:11:43 +01:00
