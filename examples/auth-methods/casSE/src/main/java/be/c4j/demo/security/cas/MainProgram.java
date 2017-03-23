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
package be.c4j.demo.security.cas;

import be.c4j.ee.security.authentication.cas.CasSEConfiguration;
import be.c4j.ee.security.authentication.credentials.cas.CasUser;
import be.c4j.ee.security.authentication.cas.TicketRequestor;
import be.c4j.ee.security.authentication.cas.info.CasInfoProvider;
import org.apache.shiro.authc.UsernamePasswordToken;

/**
 *
 */

public class MainProgram {

    public static void main(String[] args) {

        CasSEConfiguration.prepareConfiguration();

        UsernamePasswordToken token = new UsernamePasswordToken("ictextern4", "1mhe&1mka");

        CasSEConfiguration configuration = new CasSEConfiguration();
        TicketRequestor requestor = new TicketRequestor(configuration);

        String grantingTicket = requestor.getGrantingTicket(token);
        System.out.println(grantingTicket);

        String serviceTicket = requestor.getServiceTicket(grantingTicket);
        System.out.println(serviceTicket);

        CasInfoProvider infoProvider = new CasInfoProvider(configuration);
        CasUser casUser = infoProvider.retrieveUserInfo(serviceTicket);
        System.out.println(casUser);
    }


}