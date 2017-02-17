package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.logout.LogoutHandler;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.inject.Specializes;
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
@Specializes
public class ClientLogoutHandler extends LogoutHandler {

    @Inject
    private UserPrincipal userPrincipal;

    @Inject
    private OctopusSSOClientConfiguration config;

    private SSODataEncryptionHandler encryptionHandler;

    @PostConstruct
    public void init() {
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
    }

    @Override
    public void preLogoutAction() {
        super.preLogoutAction();

        String url = config.getSSOServer() + "/octopus/sso/logout";
        try {
            sendRequest(url);
        } catch (IOException e) {
            // FIXME
            e.printStackTrace();
        }
    }

    private void sendRequest(String url) throws IOException {


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
