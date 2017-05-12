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
package be.c4j.ee.security.credentials.authentication.jwt.client.rest;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.filter.ErrorInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;

/**
 *
 */

public abstract class AbstractSCSRestClient {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    protected Client client;

    protected Invocation.Builder createRequestBuilder(String url, URLArgument[] urlArguments) {
        WebTarget target = client.target(url);
        target = addArguments(target, urlArguments);
        return target.request();
    }

    private WebTarget addArguments(WebTarget target, URLArgument[] urlArguments) {
        WebTarget result = target;
        for (URLArgument urlArgument : urlArguments) {
            result = result.queryParam(urlArgument.getArgName(), urlArgument.getArgValue());
        }
        return result;
    }

    protected void handleErrorReturns(String url, Response response, String httpMethod) {
        if (response.getStatus() == 401) {
            ErrorInfo errorInfo = response.readEntity(ErrorInfo.class);
            throw new OctopusUnauthorizedException(errorInfo.getMessage(), getURLMessageWhenException("Unauthorized", url, httpMethod));
        }
        if (response.getStatus() == 404) {
            throw new OctopusConfigurationException(getURLMessageWhenException("Unknown endpoint", url, httpMethod));
        }
        if (response.getStatus() == 500) {
            String body = response.readEntity(String.class);
            logger.error(String.format("Received status 500 when calling '%s'. body contents is '%s'", url, body));
            throw new OctopusUnexpectedException(getURLMessageWhenException("Unexpected exception", url, httpMethod));
        }
    }


    private String getURLMessageWhenException(String errorType, String url, String httpMethod) {
        return String.format("%s during call to '%s' (%s)", errorType, url, httpMethod);
    }


}
