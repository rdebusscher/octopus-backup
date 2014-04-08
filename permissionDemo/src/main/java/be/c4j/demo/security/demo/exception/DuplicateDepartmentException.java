package be.c4j.demo.security.demo.exception;

/**
 *
 */
public class DuplicateDepartmentException extends DemoBusinessException {

    @Override
    String getMessageKey() {
        return "{error.department.already.exists}";
    }
}
