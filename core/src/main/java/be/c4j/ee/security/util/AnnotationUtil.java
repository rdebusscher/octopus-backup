package be.c4j.ee.security.util;

import be.c4j.ee.security.permission.NamedPermission;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class AnnotationUtil {

    private AnnotationUtil() {
    }

    public static <T extends NamedPermission> T[] getValue(Annotation someCustomNamedCheck) {
        T[] result = null;
        for (Method method : someCustomNamedCheck.getClass().getDeclaredMethods()) {
            if ("value".equals(method.getName())) {
                try {
                    result = (T[]) method.invoke(someCustomNamedCheck, null);

                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                } catch (InvocationTargetException e) {
                    e.printStackTrace();
                }
            }
        }

        return result;
    }
}
