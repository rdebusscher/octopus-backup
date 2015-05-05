/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.interceptor.checks;

import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class AnnotationCheckFactory {

    private List<SecurityCheck> securityChecks;

    @PostConstruct
    public void init() {
        securityChecks = BeanProvider.getContextualReferences(SecurityCheck.class, true);
    }

    public SecurityCheck getCheck(Object annotation) {
        SecurityCheck result = null;
        Iterator<SecurityCheck> iterator = securityChecks.iterator();
        while (result == null && iterator.hasNext()) {
            SecurityCheck securityCheck = iterator.next();
            if (securityCheck.hasSupportFor(annotation)) {
                result = securityCheck;
            }
        }
        return result;
    }
}
