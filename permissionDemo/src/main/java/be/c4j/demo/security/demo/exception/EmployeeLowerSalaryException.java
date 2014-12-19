package be.c4j.demo.security.demo.exception;

/**
 *
 */
public class EmployeeLowerSalaryException extends DemoBusinessException {

    String getMessageKey() {
        return "{error.employee.salary.lowered}";
    }
}
