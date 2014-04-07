/*
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */
package be.c4j.ee.security.event;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationListener;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.PrincipalCollection;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

/**
 *
 */
public class AuthenticationExceptionListener implements AuthenticationListener {
    @Override
    public void onSuccess(AuthenticationToken token, AuthenticationInfo info) {
        // Only interested in failures due to configuration problems
    }

    @Override
    public void onFailure(AuthenticationToken token, AuthenticationException ae) {
        if (ae instanceof OctopusConfigurationException) {
            FacesMessage fatalMsg = new FacesMessage(FacesMessage.SEVERITY_FATAL, ae.getMessage(), ae.getMessage());
            FacesContext.getCurrentInstance().addMessage(null, fatalMsg);
        }
    }

    @Override
    public void onLogout(PrincipalCollection principals) {
        // Only interested in failures due to configuration problems
    }
}
