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
package be.c4j.ee.security.view;

/**
 * @author Rudy De Busscher
 */

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.Map;

/**
 * Implementation of the {@link javax.interceptor.InvocationContext} interface.
 */
public class InvocationContextImpl implements InvocationContext {

    private Object target;

    private Object[] parameters;

    public InvocationContextImpl(Object someTarget, Object[] parameters) {
        this.target = someTarget;
        this.parameters = parameters;
    }

    @Override
    public Object getTarget() {
        return target;
    }

    @Override
    public Method getMethod() {
        return null;
    }

    @Override
    public Object[] getParameters() {
        return parameters;
    }

    @Override
    public void setParameters(Object[] someParameters) {
        parameters = someParameters;
    }

    @Override
    public Map<String, Object> getContextData() {
        return null;
    }

    @Override
    public Object proceed() throws Exception {
        return null;
    }

    @Override
    public Object getTimer() {
        return null;
    }
}