package be.c4j.demo.security.demo.model;

import java.util.Date;

/**
 * This is an entity object in production type application
 */
public class Employee {

    private Long id;
    private String name;
    private Date hireDate;
    private double salary;
    private Employee manager;
    private Department department;

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

    public Date getHireDate() {
        return hireDate;
    }

    public void setHireDate(Date hireDate) {
        this.hireDate = hireDate;
    }

    public double getSalary() {
        return salary;
    }

    public void setSalary(double salary) {
        this.salary = salary;
    }

    public Employee getManager() {
        return manager;
    }

    public void setManager(Employee manager) {
        this.manager = manager;
    }

    public Department getDepartment() {
        return department;
    }

    public void setDepartment(Department department) {
        this.department = department;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {return true;}
        if (o == null || getClass() != o.getClass()) {return false;}

        Employee employee = (Employee) o;

        if (!hireDate.equals(employee.hireDate)) {return false;}
        if (!name.equals(employee.name)) {return false;}

        return true;
    }

    @Override
    public int hashCode() {
        int result = name.hashCode();
        result = 31 * result + hireDate.hashCode();
        return result;
    }
}
