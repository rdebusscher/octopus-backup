package be.c4j.ee.security.sso.client;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

/**
 *
 */

public class OpenIdVariableClientData {

    private State state;
    private Nonce nonce;
    private String rootURL;

    public OpenIdVariableClientData(String rootURL) {
        this.rootURL = rootURL;
        // Generate State
        state = new State();

        // Generate nonce
        nonce = new Nonce();
    }

    public State getState() {
        return state;
    }

    public Nonce getNonce() {
        return nonce;
    }

    public String getRootURL() {
        return rootURL;
    }
}
