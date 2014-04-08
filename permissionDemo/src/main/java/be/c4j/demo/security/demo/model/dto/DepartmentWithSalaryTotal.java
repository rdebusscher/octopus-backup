package be.c4j.demo.security.demo.model.dto;

import be.c4j.demo.security.demo.model.Department;

/**
 *
 */
public class DepartmentWithSalaryTotal extends Department {

    private double salaryTotal;

    public DepartmentWithSalaryTotal(Department department, double salaryTotal) {
        setId(department.getId());
        setName(department.getName());
        setManager(department.getManager());
        this.salaryTotal = salaryTotal;
    }

    public double getSalaryTotal() {
        return salaryTotal;
    }

    public void setSalaryTotal(double salaryTotal) {
        this.salaryTotal = salaryTotal;
    }
}
