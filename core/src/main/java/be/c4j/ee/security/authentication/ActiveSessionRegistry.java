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
package be.c4j.ee.security.authentication;

import javax.enterprise.context.ApplicationScoped;
import java.util.HashMap;
import java.util.Map;

/**
 * FIXME Not fully used I guess. Verify!!
 */
@ApplicationScoped
public class ActiveSessionRegistry {

    private Map<String, Object> tokenPrincipalMapping = new HashMap<String, Object>();

    public void startSession(String token, Object principle) {
        tokenPrincipalMapping.put(token, principle);
    }

    public boolean isSessionActive(Object principle) {
        return tokenPrincipalMapping.containsValue(principle);
    }

    public void endSession(String token) {
        tokenPrincipalMapping.remove(token);
    }

    public void endAll() {
        tokenPrincipalMapping.clear();
    }
}
