/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.c4j.ee.security.authentication.cas;

import be.c4j.ee.security.authentication.cas.exception.CasAuthenticationException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;

/**
 *
 */
// NO CDI bean as it must be used in SE programs (and not everyone uses CDI 2.x)
public class TicketRequestor {

    private Logger logger = LoggerFactory.getLogger(TicketRequestor.class);

    private static final String V1_TICKETS = "/v1/tickets";
    private static final String UTF_8 = "UTF-8";
    private CasSEConfiguration configuration;

    public TicketRequestor(CasSEConfiguration configuration) {
        this.configuration = configuration;
    }

    public String getGrantingTicket(UsernamePasswordToken usernamePasswordToken) {
        String result = null;
        try {
            URL casEndpoint = new URL(configuration.getSSOServer() + V1_TICKETS);
            HttpURLConnection connection = (HttpURLConnection) casEndpoint.openConnection();

            prepareConnection(connection);

            String body = defineBody(usernamePasswordToken);

            writeBody(connection, body);

            int status = connection.getResponseCode();
            if (status == 201) {

                String location = connection.getHeaderField("Location");
                int pos = location.indexOf(V1_TICKETS);
                result = location.substring(pos + V1_TICKETS.length() + 1);
            }
            if (status == 401) {
                throw new CasAuthenticationException("OCT-CAS-021 : Authentication failed for credentials on the CAS server");
            }
            if (status == 404) {
                logger.warn("POST to CAS ticket URL endpoint failed");
                throw new CasAuthenticationException("OCT-CAS-022 : Invalid CAS ticket URL endpoint");
            }

            if (result == null) {
                logger.warn(String.format("POST to CAS ticket URL endpoint failed with status %s and contains response : %s", status, readResponseBody(connection)));
                throw new CasAuthenticationException("OCT-CAS-023 : Exception calling CAS ticket URL endpoint");

            }

        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }

        return result;

    }

    private void writeBody(HttpURLConnection connection, String body) throws IOException {
        OutputStream os = connection.getOutputStream();
        os.write(body.getBytes(UTF_8));
        os.close();
    }

    private String defineBody(UsernamePasswordToken usernamePasswordToken) throws UnsupportedEncodingException {
        String usernameEncoded = URLEncoder.encode(usernamePasswordToken.getUsername(), UTF_8);
        String passwordEncoded = URLEncoder.encode(String.valueOf(usernamePasswordToken.getPassword()), UTF_8);
        return String.format("username=%s&password=%s", usernameEncoded, passwordEncoded);
    }

    private void prepareConnection(HttpURLConnection con) throws ProtocolException {
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    }

    private String readResponseBody(HttpURLConnection con) {
        StringBuilder result = new StringBuilder();
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                result.append(inputLine).append("\n");
            }
            in.close();
        } catch (IOException e) {
            result.append("Reading response lead to : ").append(e.getMessage());
        }

        return result.toString();
    }


    public String getServiceTicket(String grantingTicket) {
        String result = null;
        try {
            URL casEndpoint = new URL(configuration.getSSOServer() + V1_TICKETS + "/" + grantingTicket);
            HttpURLConnection connection = (HttpURLConnection) casEndpoint.openConnection();

            prepareConnection(connection);

            String body = defineBody(configuration.getCASService());

            writeBody(connection, body);

            int status = connection.getResponseCode();
            if (status == 200) {

                result = readResponseBody(connection).replace("\n", "");
            }

            if (result == null) {
                logger.warn(String.format("POST to CAS ticket URL endpoint with TGT failed with status %s and contains response : %s", status, readResponseBody(connection)));
                throw new CasAuthenticationException("OCT-CAS-023 : Exception calling CAS ticket URL endpoint");

            }

        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }
        return result;
    }

    private String defineBody(String casService) throws UnsupportedEncodingException {
        String casServiceEncoded = URLEncoder.encode(casService, UTF_8);
        return String.format("service=%s", casServiceEncoded);

    }
}
