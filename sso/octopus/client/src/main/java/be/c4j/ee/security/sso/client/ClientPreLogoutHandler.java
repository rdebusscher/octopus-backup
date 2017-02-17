package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.event.LogoutEvent;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import static javax.ws.rs.core.HttpHeaders.USER_AGENT;

/**
 *
 */
@ApplicationScoped
public class ClientPreLogoutHandler {

    @Inject
    private OctopusSSOClientConfiguration config;

    private SSODataEncryptionHandler encryptionHandler;

    @PostConstruct
    public void init() {
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
    }


    public void preLogoutAction(@Observes LogoutEvent logoutEvent) {
        String url = config.getSSOServer() + "/octopus/sso/logout";
        try {
            sendRequest(url, logoutEvent.getPrincipal());
        } catch (IOException e) {
            // FIXME
            e.printStackTrace();
        }
    }

    private void sendRequest(String url, UserPrincipal userPrincipal) throws IOException {

        // FIXME, first draft, can be improved / cleaned up.
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();

        // optional default is GET
        con.setRequestMethod("GET");

        //add request header
        con.setRequestProperty("User-Agent", USER_AGENT);

        OctopusSSOUser octopusUser = (OctopusSSOUser) userPrincipal.getInfo().get("token");

        String token = octopusUser.getToken();
        if (encryptionHandler != null) {
            con.setRequestProperty("x-api-key", config.getSSOApiKey());

            token = encryptionHandler.encryptData(token, config.getSSOApiKey());
        }

        con.setRequestProperty("Authorization", "Bearer " + token);
        int responseCode = con.getResponseCode();
        System.out.println("\nSending 'GET' request to URL : " + url);
        System.out.println("Response Code : " + responseCode);

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        //print result
        System.out.println(response.toString());
    }
}
