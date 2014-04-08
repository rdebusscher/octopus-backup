package be.c4j.demo.security.demo.view;

import be.c4j.demo.security.demo.service.DepartmentService;

import javax.enterprise.inject.Model;
import javax.inject.Inject;

/**
 *
 */
@Model
public class DepartmentCreateBean {

    @Inject
    private DepartmentService departmentService;

    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void saveDepartment() {
        departmentService.createDepartment(name);
    }
}
