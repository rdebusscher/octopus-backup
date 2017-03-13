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
package be.c4j.ee.security.sso.server.client;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 *
 */

public class ClientInfoTest {


    @Test
    public void getActualCallbackURL_octopusClient() {
        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/");
        clientInfo.setOctopusClient(true);

        assertThat(clientInfo.getActualCallbackURL()).isEqualTo("http://localhost:8080/sso-app2/octopus/sso/SSOCallback");
    }

    @Test
    public void getActualCallbackURL_otherClient() {
        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/data");
        clientInfo.setOctopusClient(false);

        assertThat(clientInfo.getActualCallbackURL()).isEqualTo("http://localhost:8080/sso-app2/data");
    }


}