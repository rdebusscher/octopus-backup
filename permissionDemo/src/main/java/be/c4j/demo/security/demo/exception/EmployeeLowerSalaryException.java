package be.c4j.demo.security.demo.exception;

/**
 *
 */
public class EmployeeLowerSalaryException extends DemoBusinessException {

    @Override
    String getMessageKey() {
        return "{error.employee.salary.lowered}";
    }
}
