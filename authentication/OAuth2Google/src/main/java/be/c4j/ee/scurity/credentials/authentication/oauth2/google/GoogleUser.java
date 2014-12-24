package be.c4j.ee.scurity.credentials.authentication.oauth2.google;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.shiro.authc.AuthenticationToken;
import org.scribe.model.Token;

import javax.security.auth.Subject;
import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class GoogleUser implements AuthenticationToken, Principal {

    @JsonProperty("id")
    private String id;

    @JsonProperty("family_name")
    private String lastName;

    @JsonProperty("name")
    private String fullName;

    @JsonProperty("picture")
    private String picture;

    @JsonProperty("gender")
    private String gender;

    @JsonProperty("locale")
    private String locale;

    @JsonProperty("email")
    private String email;

    @JsonProperty("link")
    private String link;

    @JsonProperty("given_name")
    private String firstName;

    @JsonProperty("hd")
    private String hd;

    @JsonProperty("verified_email")
    private boolean verifiedEmail;

    @JsonIgnore
    private Token token;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public String getGender() {
        return gender;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getHd() {
        return hd;
    }

    public void setHd(String hd) {
        this.hd = hd;
    }

    public boolean isVerifiedEmail() {
        return verifiedEmail;
    }

    public void setVerifiedEmail(boolean verifiedEmail) {
        this.verifiedEmail = verifiedEmail;
    }

    public boolean isLoggedOn() {
        return id != null;
    }

    public Token getToken() {
        return token;
    }

    @JsonIgnore
    public Map<Serializable, Serializable> getUserInfo() {
        Map<Serializable, Serializable> result = new HashMap<Serializable, Serializable>();
        result.put("picture", picture);
        result.put("gender", gender);
        result.put("hd", hd);
        result.put("locale", locale);
        return result;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("GoogleUser{");
        sb.append("id='").append(id).append('\'');
        sb.append(", lastName='").append(lastName).append('\'');
        sb.append(", fullName='").append(fullName).append('\'');
        sb.append(", picture='").append(picture).append('\'');
        sb.append(", gender='").append(gender).append('\'');
        sb.append(", email='").append(email).append('\'');
        sb.append(", link='").append(link).append('\'');
        sb.append(", firstName='").append(firstName).append('\'');
        sb.append(", hd='").append(hd).append('\'');
        sb.append(", verifiedEmail=").append(verifiedEmail);
        sb.append('}');
        return sb.toString();
    }

    @Override
    public String getName() {
        return fullName;
    }

    public boolean implies(Subject subject) {
        if (subject == null) {
            return false;
        }
        return subject.getPrincipals().contains(this);
    }

    @Override
    public Object getPrincipal() {
        return new GooglePrincipal(id, email);
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    public static class GooglePrincipal {
        private String id;
        private String email;

        public GooglePrincipal(String id, String email) {
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
