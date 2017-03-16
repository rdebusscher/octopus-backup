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
package be.c4j.ee.security.sso.client.callback;

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import com.nimbusds.oauth2.sdk.ErrorObject;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@ApplicationScoped
public class CallbackErrorHandler {

    public void showErrorMessage(HttpServletResponse httpServletResponse, ErrorObject errorObject) {
        try {
            httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            httpServletResponse.getWriter().println(errorObject.getCode() + " : " + errorObject.getDescription());
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }

    }

}
