package be.c4j.ee.security.token;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
public class MultipleCredentialsMatcher implements CredentialsMatcher {

    private List<CredentialsMatcher> octopusDefinedMatchers;

    private List<CredentialsMatcher> applicationDefinedMatchers;

    public MultipleCredentialsMatcher() {
        octopusDefinedMatchers = new ArrayList<CredentialsMatcher>();
        octopusDefinedMatchers.add(new SimpleCredentialsMatcher());

        applicationDefinedMatchers = new ArrayList<CredentialsMatcher>();
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        boolean result = false;
        Iterator<CredentialsMatcher> iterator = applicationDefinedMatchers.iterator();
        while (!result && iterator.hasNext()) {
            CredentialsMatcher matcher = iterator.next();
            result = matcher.doCredentialsMatch(token, info);
        }

        iterator = octopusDefinedMatchers.iterator();
        while (!result && iterator.hasNext()) {
            CredentialsMatcher matcher = iterator.next();
            result = matcher.doCredentialsMatch(token, info);
        }

        return result;
    }

    public void setMatcher(CredentialsMatcher credentialsMatcher) {
        if (!applicationDefinedMatchers.contains(credentialsMatcher)) {
            applicationDefinedMatchers.add(credentialsMatcher);
        }
    }
}
