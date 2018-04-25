/*
 * Copyright 2014-2018 Rudy De Busscher
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
package be.c4j.ee.security.credentials.ldap;

import be.c4j.ee.security.authentication.ExternalPasswordAuthenticationInfo;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import java.util.*;

import static java.util.Collections.list;
import static javax.naming.Context.*;

public class LDAPCredentialsMatcher implements CredentialsMatcher, Initializable {

    private static final Logger LOGGER = LoggerFactory.getLogger(LDAPCredentialsMatcher.class);

    private String ldapURL;
    private String ldapBindDN;
    private String ldapBindCredential;
    private String ldapUserFilter;
    private String ldapCallerNameAttribute;
    private String ldapCallerBaseSearch;

    private LDAPGroupsNeeded ldapGroupsNeeded;
    private String groupFilter;
    private String ldapGroupSearchBase;
    private String memberOfAttribute;
    private String ldapGroupNameAttribute;

    public void init() {
        LDAPConfiguration ldapConfiguration = BeanProvider.getContextualReference(LDAPConfiguration.class);
        // Done for caching purposes
        ldapURL = ldapConfiguration.getLDAPURL();
        ldapBindDN = ldapConfiguration.getLDAPBindDN();
        ldapBindCredential = ldapConfiguration.getLDAPBindCredential();

        ldapUserFilter = ldapConfiguration.getLDAPUserFilter();
        ldapCallerNameAttribute = ldapConfiguration.getLDAPCallerNameAttribute();
        ldapCallerBaseSearch = ldapConfiguration.getLDAPCallerBaseSearch();

        ldapGroupsNeeded = ldapConfiguration.getLDAPGroupsLoaded();
        groupFilter = ldapConfiguration.getLDAPGroupFilter();
        ldapGroupSearchBase = ldapConfiguration.getLDAPGroupBaseSearch();
        memberOfAttribute = ldapConfiguration.getLDAPCallerMemberOfAttribute();
        ldapGroupNameAttribute = ldapConfiguration.getLDAPGroupNameAttribute();
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            LdapContext searchContext = createLdapContext(ldapURL, ldapBindDN, ldapBindCredential);
            if (searchContext == null) {
                throw new OctopusConfigurationException("Could not connect to LDAP, please check configuration parameters 'ldap.bindDN' and 'ldap.bindCredential'");
            }
            try {
                LDAPUserData callerData = searchCaller(searchContext, usernamePasswordToken.getUsername());
                if (callerData == null) {
                    return false; // User not found
                }

                LdapContext callerContext = createLdapContext(ldapURL, callerData.getCallerDN(), new String(usernamePasswordToken.getPassword()));
                if (callerContext == null) {
                    return false;  // Password was invalid
                }
                Set<String> groups = null;
                try {
                    if (ldapGroupsNeeded != LDAPGroupsNeeded.NO) {
                        groups = retrieveGroupsForCallerDn(callerContext, callerData.getCallerDN());
                    }

                } finally {
                    closeContext(callerContext);
                }

                updateUserInfo((ExternalPasswordAuthenticationInfo) info, callerData, groups);
                return true;
            } finally {
                closeContext(searchContext);
            }
        }
        return false;
    }

    private void updateUserInfo(ExternalPasswordAuthenticationInfo info, LDAPUserData callerData, Set<String> groups) {
        // When developer has set 'ldap.nameAttribute' to null or blanco -> don't set the name from LDAP
        if (StringUtils.hasText(ldapCallerNameAttribute)) {
            info.setName(callerData.getAttributes().get(ldapCallerNameAttribute));
        }
        // Set all node attributes from LDAP as additional info.
        for (Map.Entry<String, String> entry : callerData.getAttributes().entrySet()) {
            if (!ldapCallerNameAttribute.equals(entry.getKey())) {
                info.addUserInfo(entry.getKey(), entry.getValue());
            }
        }

        if (!CollectionUtils.isEmpty(groups)) {
            AuthorizationInfoBuilder authorizationInfoBuilder = new AuthorizationInfoBuilder();
            authorizationInfoBuilder.addRolesByName(groups);
            info.addAuthorizationInfo(authorizationInfoBuilder.build());
        }
    }

    private Set<String> retrieveGroupsForCallerDn(LdapContext searchContext, String callerDn) {

        if (ldapGroupsNeeded == LDAPGroupsNeeded.CALLER) {
            return retrieveGroupsFromCallerObject(callerDn, searchContext);
        } else {
            return retrieveGroupsBySearching(callerDn, searchContext);
        }
    }

    private Set<String> retrieveGroupsBySearching(String callerDn, LdapContext searchContext) {

        List<SearchResult> searchResults = searchGroups(searchContext, callerDn);

        Set<String> groups = new HashSet<String>();
        try {
            for (SearchResult searchResult : searchResults) {
                Attribute attribute = searchResult.getAttributes().get(ldapGroupNameAttribute);
                if (attribute != null) {
                    for (Object group : list(attribute.getAll())) {
                        if (group != null) {
                            groups.add(group.toString());
                        }
                    }
                }
            }
        } catch (NamingException e) {
            throw new OctopusUnexpectedException(e);
        }
        return groups;
    }

    private Set<String> retrieveGroupsFromCallerObject(String callerDn, LdapContext searchContext) {
        try {
            Attributes attributes = searchContext.getAttributes(callerDn, new String[]{memberOfAttribute});
            Attribute attribute = attributes.get(memberOfAttribute);

            Set<String> groups = new HashSet<String>();
            if (attribute != null) {
                for (Object group : list(attribute.getAll())) {
                    if (group != null) {
                        String groupName = getGroupNameFromDn(group.toString(), ldapGroupNameAttribute);
                        if (groupName != null) {
                            groups.add(groupName);
                        }
                    }
                }
            }
            return groups;
        } catch (NamingException e) {
            throw new OctopusUnexpectedException(e);
        }
    }

    private static String getGroupNameFromDn(String dnString, String groupNameAttribute) throws NamingException {
        LdapName dn = new LdapName(dnString);  // may throw InvalidNameException
        Attribute attribute = dn.getRdn(dn.size() - 1).toAttributes().get(groupNameAttribute);
        if (attribute == null) {
            // We were configured with the wrong group name attribute
            throw new OctopusConfigurationException("Group name attribute '" + groupNameAttribute + "' not found for DN: " + dnString);
        }
        return attribute.get(0).toString();
    }

    private List<SearchResult> searchGroups(LdapContext searchContext, String callerDn) {

        String filter;
        // Filter should have exactly one "%s", where callerDn will be substituted.
        filter = String.format(groupFilter, callerDn);

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        //controls.setCountLimit((long)ldapIdentityStoreDefinition.maxResults());
        //controls.setTimeLimit(ldapIdentityStoreDefinition.readTimeout());
        controls.setReturningAttributes(new String[]{ldapGroupNameAttribute});

        return search(searchContext, ldapGroupSearchBase, filter, controls);
    }

    private LDAPUserData searchCaller(LdapContext searchContext, String callerName) {

        String filter = String.format(ldapUserFilter, callerName);

        List<SearchResult> callerDn =
                search(searchContext, ldapCallerBaseSearch, filter, getCallerSearchControls());

        if (callerDn.size() > 1) {
            logMultipleUsers(callerName, callerDn);
            return null; // Multiple results so we can't determine the user uniquely.
        }
        if (callerDn.size() == 1) {
            // get the fully qualified identification like uid=rudy,ou=caller,dc=atbash,dc=be
            return new LDAPUserData(callerDn.get(0));
        }

        return null;
    }

    private void logMultipleUsers(String callerName, List<SearchResult> callerDn) {
        StringBuilder builder = new StringBuilder();
        for (SearchResult searchResult : callerDn) {
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append(searchResult.getNameInNamespace());
        }
        LOGGER.warn(String.format("LDAP error: User search for username '%s' gives multiple results %s", callerName, builder.toString()));
    }

    private static List<SearchResult> search(LdapContext searchContext, String searchBase, String searchFilter, SearchControls controls) {
        try {
            return list(searchContext.search(searchBase, searchFilter, controls));
        } catch (NameNotFoundException e) {
            throw new OctopusConfigurationException("Invalid searchBase");
        } catch (InvalidSearchFilterException e) {
            throw new OctopusConfigurationException("Invalid search filter");
        } catch (InvalidSearchControlsException e) {
            throw new OctopusConfigurationException("Invalid search controls");
        } catch (Exception e) {
            throw new OctopusUnexpectedException(e);
        }
    }

    private SearchControls getCallerSearchControls() {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        return controls;
    }

    private static LdapContext createLdapContext(String url, String bindDn, String bindCredential) {
        // Hashtable required by InitialLdapContext
        Hashtable<String, String> environment = new Hashtable<String, String>();

        environment.put(INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(PROVIDER_URL, url);

        environment.put(SECURITY_AUTHENTICATION, "simple");
        if (StringUtils.hasText(bindDn)) {
            environment.put(SECURITY_PRINCIPAL, bindDn);
            environment.put(SECURITY_CREDENTIALS, bindCredential);
        }

        try {
            return new InitialLdapContext(environment, null);
        } catch (AuthenticationException e) {
            return null; // When authentication is wrong, return null;
        } catch (CommunicationException e) {
            throw new OctopusConfigurationException("LDAP URL defined in parameter 'ldap.url' is invalid.");
        } catch (Exception e) {
            throw new OctopusUnexpectedException(e);
        }

    }

    private static void closeContext(LdapContext ldapContext) {
        try {
            if (ldapContext != null) {
                ldapContext.close();
            }
        } catch (NamingException e) {
            throw new OctopusUnexpectedException(e);
        }
    }

    private static class LDAPUserData {
        private String callerDN;
        private Map<String, String> attributes;

        LDAPUserData(SearchResult searchResult) {
            callerDN = searchResult.getNameInNamespace();

            attributes = new HashMap<String, String>();
            NamingEnumeration<? extends Attribute> enumeration = searchResult.getAttributes().getAll();
            try {
                StringBuilder attributeValue = new StringBuilder();
                while (enumeration.hasMore()) {
                    Attribute attribute = enumeration.next();
                    if ("userPassword".equals(attribute.getID())) {
                        continue;
                    }
                    attributeValue.setLength(0);
                    for (int i = 0; i < attribute.size(); i++) {
                        if (attributeValue.length() > 0) {
                            attributeValue.append(", ");
                        }
                        attributeValue.append(attribute.get(i));
                    }
                    attributes.put(attribute.getID(), attributeValue.toString());
                }
            } catch (NamingException e) {
                throw new OctopusUnexpectedException(e);
            }
        }

        String getCallerDN() {
            return callerDN;
        }

        Map<String, String> getAttributes() {
            return attributes;
        }
    }

}
