package be.c4j.demo.security.demo.view;

import be.c4j.demo.security.demo.model.dto.UserWithPermission;
import be.c4j.demo.security.demo.service.InMemoryDatabase;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.List;

/**
 *
 */
@ApplicationScoped
@Named
public class InfoBean {

    @Inject
    private InMemoryDatabase database;

    public List<UserWithPermission> getUsers() {
        return database.getAvailableUsersWithInfo();
    }
}
