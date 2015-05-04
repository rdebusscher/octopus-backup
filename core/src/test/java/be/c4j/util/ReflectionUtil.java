package be.c4j.util;

import java.lang.reflect.Field;

/**
 *
 */
public final class ReflectionUtil {

    private ReflectionUtil() {
    }

    /**
     * Injects objects into the target (private) fields by matching the type.
     *
     * @param target       The target object where the dependencies are injected
     * @param dependencies The objects we like to set into the target.
     * @throws IllegalAccessException Should not happen since we overrule the accessibility
     */
    public static void injectDependencies(final Object target, final Object... dependencies) throws IllegalAccessException {
        Class targetClass = target.getClass();
        while (targetClass != null && targetClass != Object.class) {
            if (targetClass.getName().contains("$")) {
                targetClass = targetClass.getSuperclass();
            }
            for (Field field : targetClass.getDeclaredFields()) {
                field.setAccessible(true);
                for (Object dependency : dependencies) {
                    if (field.getType().isAssignableFrom(dependency.getClass())) {
                        field.set(target, dependency);
                    }
                }

            }
            targetClass = targetClass.getSuperclass();
        }
    }
}
