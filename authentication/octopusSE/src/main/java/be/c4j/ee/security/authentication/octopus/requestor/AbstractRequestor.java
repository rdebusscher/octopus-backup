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
package be.c4j.ee.security.authentication.octopus.requestor;

import be.c4j.ee.security.authentication.octopus.OctopusSEConfiguration;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */

public class AbstractRequestor {

    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    protected OctopusSEConfiguration configuration;

    public AbstractRequestor(OctopusSEConfiguration configuration) {
        this.configuration = configuration;
    }

    protected void showRequest(int correlationId, HTTPRequest httpRequest) {
        String query = httpRequest.getQuery();
        String authorization = httpRequest.getAuthorization();

        if (query != null) {
            if (authorization != null) {
                logger.info(String.format("(correlationId %5d) Sending to %s with Authorization header %s and body %s", correlationId, httpRequest.getURL().toExternalForm(), authorization, query));
            } else {
                logger.info(String.format("(correlationId %5d) Sending to %s with body %s", correlationId, httpRequest.getURL().toExternalForm(), query));
            }
        } else {

            if (authorization != null) {
                logger.info(String.format("(correlationId %5d) Sending to %s with Authorization header %s ", correlationId, httpRequest.getURL().toExternalForm(), authorization));
            } else {
                logger.info(String.format("(correlationId %5d) Sending to %s", correlationId, httpRequest.getURL().toExternalForm()));
            }
        }

    }

    protected void showResponse(int correlationId, HTTPResponse response) {
        logger.info(String.format("(correlationId %5d) Received response with status %s and content %s ", correlationId, response.getStatusCode(), response.getContent()));
    }


}
