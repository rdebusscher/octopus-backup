package be.c4j.ee.security.interceptor;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.Map;

/**
 *
 */
public class TestInvocationContext implements InvocationContext {

    private Object target;
    private Method method;
    private Object[] parameters;

    public TestInvocationContext(Object target, Method method) {
        this.target = target;
        this.method = method;
    }


    @Override
    public Object getTarget() {
        return target;
    }

    @Override
    public Object getTimer() {
        return null;
    }

    @Override
    public Method getMethod() {
        return method;
    }

    @Override
    public Object[] getParameters() {
        return parameters;
    }

    @Override
    public void setParameters(Object[] objects) {
        parameters = objects;
    }

    @Override
    public Map<String, Object> getContextData() {
        return null;
    }

    @Override
    public Object proceed() throws Exception {
        return method.invoke(target, parameters);
    }
}
