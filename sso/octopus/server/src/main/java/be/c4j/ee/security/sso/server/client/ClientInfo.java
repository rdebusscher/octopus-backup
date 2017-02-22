package be.c4j.ee.security.sso.server.client;

/**
 *
 */
public class ClientInfo {


    private String callbackURL;
    private boolean octopusClient;

    public String getCallbackURL() {
        return callbackURL;
    }

    public void setCallbackURL(String callbackURL) {
        this.callbackURL = callbackURL;
    }

    public boolean isOctopusClient() {
        return octopusClient;
    }

    public void setOctopusClient(boolean octopusClient) {
        this.octopusClient = octopusClient;
    }
}
