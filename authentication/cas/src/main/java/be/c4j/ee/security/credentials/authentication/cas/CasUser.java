package be.c4j.ee.security.credentials.authentication.cas;

import org.apache.shiro.authc.AuthenticationToken;

import java.io.Serializable;
import java.security.Principal;
import java.util.Map;

/**
 *
 */
public class CasUser implements AuthenticationToken, Principal {

    public static final String CAS_USER_INFO = "CASUserInfo";

    private String ticket;
    private String userName;
    private String email;
    private Map<Serializable, Serializable> userInfo;

    public CasUser(String ticket) {
        this.ticket = ticket;
    }

    public String getTicket() {
        return ticket;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserName() {
        return userName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Map<Serializable, Serializable> getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(Map<Serializable, Serializable> userInfo) {
        this.userInfo = userInfo;
    }

    @Override
    public Object getPrincipal() {
    /* FIXME email ? */
        return new CasPrincipal(userName, null);
    }

    @Override
    public Object getCredentials() {
        return ticket;
    }

    @Override
    public String getName() {
        return userName;
    }

    public static class CasPrincipal {
        private String id;
        private String email;

        public CasPrincipal(String id, String email) {
            this.id = id;
            this.email = email;
        }

        public String getId() {
            return id;
        }

        public String getEmail() {
            return email;
        }
    }
}
