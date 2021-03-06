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
package be.c4j.ee.security;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * Allows to wrap an existing (from EJB execution for example) InvocationContext but adds additional ContextData.
 * Important, when the context data (Map) parameter of the constructor contains a key which also exists in the wrapped InvocationContext instance, it is overwritten by the wrapped key value.
 * See InvocationContextWrapperTest.
 */

public class InvocationContextWrapper implements InvocationContext {

    private InvocationContext wrapped;
    private Map<String, Object> contextData;

    public InvocationContextWrapper(InvocationContext wrapped, Map<String, Object> contextData) {
        this.wrapped = wrapped;
        this.contextData = contextData;
    }

    @Override
    public Object getTarget() {
        return wrapped.getTarget();
    }

    @Override
    public Object getTimer() {
        return wrapped.getTimer();
    }

    @Override
    public Method getMethod() {
        return wrapped.getMethod();
    }

    @Override
    public Object[] getParameters() {
        return wrapped.getParameters();
    }

    @Override
    public void setParameters(Object[] objects) {
        wrapped.setParameters(objects);
    }

    @Override
    public Map<String, Object> getContextData() {
        Map<String, Object> result = new HashMap<String, Object>(contextData);
        Map<String, Object> data = wrapped.getContextData();
        if (data != null) {
            result.putAll(data);
        }
        return result;
    }

    @Override
    public Object proceed() throws Exception {
        return wrapped.proceed();
    }
}
