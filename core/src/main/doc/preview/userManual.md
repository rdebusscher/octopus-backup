Octopus Framework
=================

C4J - Rudy De Busscher \<rudy.debusscher@c4j.be\>  
 version 0.9.3-SNAPSHOT, 08/04/2014

Introduction
------------

### What is Octopus?

Octopus is a Permission based security framework for Java EE, which is
able to secure URL’s, EJB and CDI method calls and JSF components with
the same code. It emphasis the Type safety approach by supporting named
permissions defined by enum constants and deeply integrating it with the
CDI mechanism.

The basis of the Octopus framework can be found in 2 blog posts.

The first one is written by balusc, [Apache Shiro, is it ready for Java
EE
6?](http://balusc.blogspot.nl/2013/01/apache-shiro-is-it-ready-for-java-ee-6.html)
about the possibilities of using **Apache Shiro** with JSF 2. This text
convinced me to use the Apache Shiro framework as a base for the Octopus
Framework. Especially the permission based nature of it was very
important.

The second blog was written by Rudy De Busscher, [JSF
Security](http://jsfcorner.blogspot.be/2011/03/jsf-security.html) where
the possibility of securing JSF components with the use of the security
code available in the **Apache MyFaces Extension CDI** (or CODI) is
described.

Based on the information in those 2 sources, combined with CDI based
configuration and type safe definitions of Named permissions with enums,
Octopus was born.

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

A `Permission` represents the ability to perform an action or access a
resource. A Permission is the most granular, or atomic, unit in a
system’s security policy.

### Domain permission

This concept is taken from Apache Shiro. In case of a domain permission,
you enlarge the concept of having a permission. The permission is
divided in 3 parts, the functional area it is assigned to, called the
domain, and also the action and the target of to the permission. In our
example, we can define all the permissions related to the functional
area department as having the *domain* **department**. And we can
imagine that we have *actions* like read, create, list and so on. And in
the case we have a very fine grained authorization policy, we can define
that some of those actions are only allowed for a certain department.
For example the department where the employee is working in. The
*target* could then be the value `own`. Other actions, like list the
name of the departments, should probably allowed by every one. And then
we can specify here the wildcard \*.

The wildcard can be very handy when we need to define a person which has
all the permissions for the domain. Then we can specify the \* for the
value of *actions*.

So from now on we will indicate the domain permissions in the following
format: domain:actions:target, for example department:list:\*

Other features of Apache Shiro related to the domain permission are also
available in the framework. See ??? for some more examples.

### Named (domain) permission

The named permission which is used by the Octopus framework, can be seen
as a kind of simplification. Instead of referring to the 3 arts of the
domain permission, we give it a name. With `DEPARTMENT_READ` we could
refer to the permission department:list:\*. This name can then be used
as some kind of *variable name* and we can use it to refer to the domain
permission in a type safe way.

Features
--------

This is the list with the most important features of Octopus

1.  Permission based framework for Java EE

2.  Secures URL, JSF components and CDI and EJB method calls

3.  Very flexible, can be easily integrated within your application

4.  Tightly integrated with CDI

5.  Type-safe definition of permissions

6.  Declarative declaration of JSF security (with tags, not using
    rendered attribute)

7.  Support for salted hashed passwords and remember me functionality

8.  Custom voter can be created for more complex security requirements

Compatibility
-------------

This is the list of (Application) servers which are tested at this
moment

Java EE 6

1.  Glassfish 3.1.2

2.  TomEE 1.6

List of application servers which will be supported before we reach the
1.0 version

Java EE 6

1.  Glassfish 3.1.2

2.  TomEE 1.6

3.  Weblogic 12.1c

Java EE 7

1.  Glassfish 4

2.  Wildfly 8

It is possible that it already works or will be working with other
versions as it is based on standards.

Setup
-----

This chapter describes the minimal steps you need to do to use the
Octopus framework in your application.

### Add library

Add the octopus artifact to your project dependencies.

        <dependency>
            <groupId>be.c4j.ee.security</groupId>
            <artifactId>octopus</artifactId>
            <version>0.9.3</version>
        </dependency>

The Octopus library has a few transient dependencies which are imported
automatically. But it also depends on CODI, which is not included by
default (see ???here??? for the explaination). For your ease, you can
include the complete JSF2 bundle of CODI.

            <dependency>
                <groupId>org.apache.myfaces.extensions.cdi.bundles</groupId>
                <artifactId>myfaces-extcdi-bundle-jsf20</artifactId>
                <version>1.0.5</version>
            </dependency>

            <!-- logging -->
            <dependency>
                <groupId>org.slf4j</groupId>
                <artifactId>slf4j-simple</artifactId>
                <version>1.6.4</version>
            </dependency>

In the above snippet, you see also that there is also a logging target
required for SLF4J. You can of course include another bridge like the
one for log4j.

### Non Maven users

??? TODO

### URL patterns protection

By just adding the Octopus jar file and his dependencies, your
application no longer deploys. It complains that it is missing a CDI
bean which implements the `SecurityDataProvider` interface. This bean is
required to supply the authentication and authorization information to
the Octopus framework. See ???configuring authentication??? and
???configuring authorization??? for the details how you can do this.

Another thing you need to do before you can start, is to create the
`/WEB-INF/securedURLs.ini` file. In this file, you can configure which
URLs need to be protected by authentication. An example is in the
following snippet

       /pages/** = user

It makes sure that all the pages within the `pages` directory and
subdirectory can’t be accessed without proper authentication. All other
pages in the root or in other directories can be viewed anonymous.

`user` is the predefined filter by Octopus/shiro that requires
authentication. The other predefined filter is called `anon` for
anonymous access. See also ??? how you can define other filters based on
named permissions and named roles.

### Login form

Whenever a user navigates to an URL which needs authentication (and he
isn’t already authenticated) the login form is shown. By default this is
`/login.xhtml` JSF page. You can use a regular JSF page for this purpose
and there is no restrictions on layout, structure or component library
which is used.

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

Requirements

1.  The user name must be bound to the `username` attribute of the
    `loginBean` like in *value="\#{loginBean.username}"*

2.  The password must be bound to the `password` attribute, like in
    *value="\#{loginBean.password}"*

3.  The actual authentication cen be performed by calling the method
    `doLogin()` by an actionListener, like the *p:commandButton*

### Named Permissions or/and named Roles

We are now at the point that the authentication works, the next thing is
the authorization we need to provide. As specified in the features
chapter, the named permissions (and named roles) can be defined by using
enumeration constants to make it more typesafe.

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
`octopusConfig.properties`, must be located in the class root (If you
are using Maven, you can place it in the `src+main/resources` directory)

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

#### Mapping named permissions to domain permissions Apache Shiro

Since Apache Shiro works with domain permissions and the verification of
the fact that the user has the appropriate rights is performed by Shiro,
We need to supply some mapping btween the domain permission and the
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
the exception

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
JSF components. By using a renderer interceptor mechanism (borrowed for
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

### SecurityDataProvider

This chapter describes how you can supply the authentication and
authorization information to Octopus.

The framework is built around the principal that the developer is
responsible for retrieving the information in the correct backed system
(like a database or LDAP system) but that there is no code present in
the framework to do this.

#### Interface

The interface `SecurityDataProvider` contains 2 methods which are called
by the Octopus framework when information is required.

    public interface SecurityDataProvider {

        AuthenticationInfo getAuthenticationInfo(UsernamePasswordToken token);

        AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals);
    }

#### getAuthenticationInfo()

This method is called whenever the framework needs to verify some
authentication information.

`AuthenticationToken` contains the user name which is specified by the
user in the login form. Based on that information, the developer has 2
possible return values:

getAuthenticationInfo() return

1.  **null** means the user name is not known

2.  **AuthenticationInfo instance** means the user name is found and all
    the required information is returned to the Octopus framework.

**UsernamePasswordToken** is defined by Apache Shiro and the
`getUsername()` method returns a *String* containing the user name
specified in the login Form.

For the return Object, you can use the `AuthenticationInfoBuilder` to
create it for you.

AuthenticationInfoBuilder methods

1.  principalId(Serializable) : Each user must be uniquely identified.
    It will also used by Apache Shiro when the authorization is
    requested.

2.  name(String) : The description for the user, like his full name.
    This can be used to put on the screen.

3.  password(Object) : The password for the user name or the hash when
    hashed passwords are used. See also ??? password mechanism ??? for a
    more complete explanation, like salted hashed passwords.

4.  realmName(String) : name for the realm. Multiple realms are not yet
    supported by Octopus.

5.  salt(Object) : The salt for the hashed password, see ??? password
    mechanism ???

6.  addUserInfo(Serializable, Serializable) : Add additional information
    about the user that can be used by custom permission voters.

7.  build() : Makes the AuthenticationInfo object.

#### getAuthorizationInfo()

The method is called when Octopus needs to known the permissions for a
certain user/principal. The parameter of the method contains the
principal information for which we need to supply the permission info.

The call to the method `principals.getPrimaryPrincipal()` returns an
instance of `UserPrincipal`, an Octopus class which contains for example
the **id** assigned to the user by using the `principalId()` method from
the *AuthenticationInfoBuilder*. It is the link between the 2 method
calls.

Based on that unique id for the user, the developer needs to return the
authentication info for that user and can make use of the
**AuthorizationInfoBuilder** to do so.

AuthorizationInfoBuilder methods.

1.  addPermission(NamedPermission) : Add the named permission to the
    user. It uses the PermissionLookup instance to translate it to an
    Apache Shiro Domain Permission.

2.  addPermissions(List\<NamedPermission\>) : Collection version of the
    previous method.

3.  addRole(NamedRole) : Add the named role to the user. It uses the
    RoleLookup instance to translate it to a simple Apache Shore
    permission.

4.  addRoles(List\<NamedRole\>) : Collection version of the previous
    method.

5.  addPermissionAndRoles(List\<? extends Permission\>) : Adds a list of
    Apache Shiro Permissions (and thus bypassing Octopus)

6.  build() : Makes the AuthorizationInfo object.

The calls to this getAuthorizationInfo() method is cached and thus only
called once for each user.

Version 0.9.3-SNAPSHOT  
 Last updated 2014-04-08 13:39:47 CEST
