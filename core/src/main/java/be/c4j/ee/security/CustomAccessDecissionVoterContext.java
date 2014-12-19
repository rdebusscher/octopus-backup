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
package be.c4j.ee.security;

/**
 * @author Rudy De Busscher
 */

import org.apache.deltaspike.security.api.authorization.AccessDecisionState;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.deltaspike.security.spi.authorization.EditableAccessDecisionVoterContext;

import javax.interceptor.InvocationContext;
import java.security.InvalidParameterException;
import java.util.*;

/**
 * Implementation of the {@link javax.interceptor.InvocationContext} interface.
 */
public class CustomAccessDecissionVoterContext implements EditableAccessDecisionVoterContext {
    private AccessDecisionState state = AccessDecisionState.INITIAL;
    private List<SecurityViolation> securityViolations;
    private Map<String, Object> metaData = new HashMap<String, Object>();
    private InvocationContext context;

    public CustomAccessDecissionVoterContext(Object someTarget, Object[] parameters) {
        context = new OctopusInvocationContext(someTarget, parameters);
    }

    public CustomAccessDecissionVoterContext(InvocationContext context) {
        this.context = context;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AccessDecisionState getState() {
        return state;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<SecurityViolation> getViolations() {
        if (securityViolations == null) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(securityViolations);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public <T> T getSource() {
        return (T) context;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSource(Object source) {
        if (!(source instanceof InvocationContext)) {
            throw new InvalidParameterException("Only InvocationContext supported");
        }
        this.context = (InvocationContext) source;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> getMetaData() {
        return Collections.unmodifiableMap(metaData);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public <T> T getMetaDataFor(String key, Class<T> targetType) {
        return (T) metaData.get(key);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void addMetaData(String key, Object metaData) {
        //TODO specify nested security calls
        this.metaData.put(key, metaData);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setState(AccessDecisionState accessDecisionVoterState) {
        if (AccessDecisionState.VOTE_IN_PROGRESS.equals(accessDecisionVoterState)) {
            securityViolations = new ArrayList<SecurityViolation>(); //lazy init
        }

        state = accessDecisionVoterState;

        if (AccessDecisionState.INITIAL.equals(accessDecisionVoterState) ||
                AccessDecisionState.VOTE_IN_PROGRESS.equals(accessDecisionVoterState)) {
            return;
        }

        //meta-data is only needed until the end of a voting process
        metaData.clear();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void addViolation(SecurityViolation securityViolation) {
        if (securityViolations == null) {
            throw new IllegalStateException(
                    AccessDecisionState.VOTE_IN_PROGRESS.name() + " is required for adding security-violations");
        }
        securityViolations.add(securityViolation);
    }
}