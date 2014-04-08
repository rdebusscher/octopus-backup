package be.c4j.demo.security.demo.model;

import java.io.Serializable;

/**
 * This is an entity object in production type application
 */
public class Department implements Serializable {

    private Long id;
    private String name;
    private Employee manager;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Employee getManager() {
        return manager;
    }

    public void setManager(Employee manager) {
        this.manager = manager;
    }
}
