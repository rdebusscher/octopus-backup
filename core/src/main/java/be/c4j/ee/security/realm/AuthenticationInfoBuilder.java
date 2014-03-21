package be.c4j.ee.security.realm;

import be.c4j.ee.security.exception.FrameworkConfigurationException;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.util.ByteSource;

import javax.enterprise.inject.Typed;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@Typed
public class AuthenticationInfoBuilder {

    private Serializable principalId;
    private String name;
    private Object password;
    private String realmName = "OctopusApp";
    private ByteSource salt;
    private Map<Serializable, Serializable> userInfo = new HashMap<Serializable, Serializable>();


    public AuthenticationInfoBuilder principalId(Serializable principalId) {
        this.principalId = principalId;
        return this;
    }

    public AuthenticationInfoBuilder name(String name) {
        this.name = name;
        return this;
    }

    public AuthenticationInfoBuilder password(Object password) {
        this.password = password;
        return this;

    }

    public AuthenticationInfoBuilder realmName(String realmName) {
        if (realmName == null || realmName.trim().length() == 0) {
            throw new FrameworkConfigurationException("Realm name can't be empty");
        }
        this.realmName = realmName;
        return this;
    }

    public AuthenticationInfoBuilder salt(ByteSource salt) {
        this.salt = salt;
        return this;
    }

    public AuthenticationInfoBuilder addUserInfo(Serializable key, Serializable value) {
        userInfo.put(key, value);
        return this;
    }

    public AuthenticationInfoBuilder addUserInfo(Map<? extends Serializable, ? extends Serializable> values) {
        userInfo.putAll(values);
        return this;
    }

    public AuthenticationInfo build() {
        UserPrincipal principal = new UserPrincipal(principalId, name);
        principal.addUserInfo(userInfo);
        AuthenticationInfo result;
        if (salt == null) {
            result = new SimpleAuthenticationInfo(principal, password, realmName);
        } else {
            result = new SimpleAuthenticationInfo(principal, password, salt, realmName);
        }
        return result;
    }
}
