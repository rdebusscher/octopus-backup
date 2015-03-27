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
package be.c4j.ee.security.producer;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Named;

public class ProducerBean {

    @Produces
    @RequestScoped
    public Subject produceShiroSubject() {
        return SecurityUtils.getSubject();
    }

    @Produces
    @RequestScoped
    @Named("userPrincipal")
    public UserPrincipal producePrincipal() {
        return (UserPrincipal) SecurityUtils.getSubject().getPrincipal();
    }

    @Produces
    @Named("loggedInUser")
    public String produceUser() {
        Object principal = SecurityUtils.getSubject().getPrincipal();
        if (principal != null) {
            return principal.toString();
        } else {
            return null;
        }
    }
}
