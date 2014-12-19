package be.c4j.demo.security.demo.exception;

/**
 *
 */
public class DuplicateDepartmentException extends DemoBusinessException {

    String getMessageKey() {
        return "{error.department.already.exists}";
    }
}
