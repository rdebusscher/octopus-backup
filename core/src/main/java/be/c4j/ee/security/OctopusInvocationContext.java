package be.c4j.ee.security;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class OctopusInvocationContext implements InvocationContext {

    private Object target;
    private Object[] parameters;

    public OctopusInvocationContext(Object target, Object[] parameters) {
        this.target = target;
        this.parameters = parameters;
    }

    @Override
    public Object getTarget() {
        return target;
    }

    @Override
    public Object getTimer() {
        // It is ok here to return null
        return null;
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
    public void setParameters(Object[] parameters) {
        this.parameters = parameters;
    }

    @Override
    public Map<String, Object> getContextData() {
        return new HashMap<String, Object>();
    }

    @Override
    public Object proceed() throws Exception {
        throw new UnsupportedOperationException("OctopusInvocationContext is no real InvocationContext but used for securing JSF Components");
    }
}
