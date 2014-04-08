package be.c4j.demo.security.permission;

import be.c4j.ee.security.permission.NamedPermission;

/**
 *
 */
public enum DemoPermission implements NamedPermission {
    ALL, DEPARTMENT_SALARY_ALL, DEPARTMENT_SALARY_MANAGER, DEPARTMENT_CREATE, EMPLOYEE_READ_ALL, EMPLOYEE_UPDATE_SALARY
}
