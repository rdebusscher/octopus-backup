package be.c4j.demo.security.demo.model;

import java.util.*;

/**
 * This is an entity object in production type application
 */
public class Principal {

    private UUID id = UUID.randomUUID();
    private Employee employee;
    private String userName;
    private String password;
    private Set<HRAppPermission> permissions = new HashSet<HRAppPermission>();

    public UUID getId() {
        return id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Employee getEmployee() {
        return employee;
    }

    public void setEmployee(Employee employee) {
        this.employee = employee;
    }

    public Set<HRAppPermission> getPermissions() {
        return permissions;
    }

    public void addPermission(HRAppPermission permission) {
        permissions.add(permission);
    }
}
