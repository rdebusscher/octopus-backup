package be.c4j.ee.security.permission;

import org.apache.myfaces.extensions.cdi.core.api.security.AbstractAccessDecisionVoter;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface CustomPermissionCheck {
    Class<? extends AbstractAccessDecisionVoter>[] value();
}
