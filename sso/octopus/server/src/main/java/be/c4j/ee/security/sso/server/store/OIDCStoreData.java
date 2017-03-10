package be.c4j.ee.security.sso.server.store;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 *
 */

public class OIDCStoreData {

    private ClientID clientId;
    private Scope scope;

    private AuthorizationCode authorizationCode;
    private BearerAccessToken accessCode;
    private IDTokenClaimsSet idTokenClaimsSet;

    public ClientID getClientId() {
        return clientId;
    }

    public void setClientId(ClientID clientId) {
        this.clientId = clientId;
    }

    public Scope getScope() {
        return scope;
    }

    public void setScope(Scope scope) {
        this.scope = scope;
    }

    public AuthorizationCode getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(AuthorizationCode authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public BearerAccessToken getAccessCode() {
        return accessCode;
    }

    public void setAccessCode(BearerAccessToken accessCode) {
        this.accessCode = accessCode;
    }

    public IDTokenClaimsSet getIdTokenClaimsSet() {
        return idTokenClaimsSet;
    }

    public void setIdTokenClaimsSet(IDTokenClaimsSet idTokenClaimsSet) {
        this.idTokenClaimsSet = idTokenClaimsSet;
    }
}
