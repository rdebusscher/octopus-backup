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
package be.c4j.ee.security.util;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;

/**
 *
 *
 */
@ApplicationScoped
public class URLUtil {

    public String determineRoot(HttpServletRequest req) {
        String result = req.getScheme() + "://" +
                req.getServerName() +
                getServerPort(req) +
                req.getContextPath();
        return result;
    }

    private String getServerPort(HttpServletRequest req) {
        String result = ':' + String.valueOf(req.getServerPort());
        if (":80".equals(result)) {
            result = "";
        }
        if (":443".equals(result)) {
            result = "";
        }
        return result;
    }

    /**
     * baseURI is the contextRoot appended with the ApplicationPath
     * TODO Document that when creating a Octopus SSO Server application Path can only be a 1 'level' (like /data, but not /octopus/data)
     *
     * @param baseURI
     * @return
     */
    public String determineRoot(URI baseURI) {
        String base = baseURI.toASCIIString();

        // Strip the trailing /
        String result = base.substring(0, base.length() - 1);

        // Find the last /
        int idx = result.lastIndexOf('/');

        return result.substring(0, idx);
    }

}
