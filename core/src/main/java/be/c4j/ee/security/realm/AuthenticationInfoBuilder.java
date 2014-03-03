package be.c4j.ee.security.realm;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.util.ByteSource;

import javax.enterprise.inject.Typed;
import java.io.Serializable;

/**
 *
 */
@Typed
public class AuthenticationInfoBuilder {

    private Serializable principalId;
    private String name;
    private Object password;
    private String realmName;
    private ByteSource salt;

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
        this.realmName = realmName;
        return this;
    }

    public AuthenticationInfoBuilder salt(ByteSource salt) {
        this.salt = salt;
        return this;
    }

    public AuthenticationInfo build() {
        UserPrincipal principal = new UserPrincipal(principalId, name);
        AuthenticationInfo result;
        if (salt == null) {
            result = new SimpleAuthenticationInfo(principal, password, realmName);
        } else {
            result = new SimpleAuthenticationInfo(principal, password, salt, realmName);
        }
        return result;
    }
}
