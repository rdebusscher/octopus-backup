package be.c4j.demo.security.demo.service;

import be.c4j.demo.security.demo.model.HRAppPermission;
import be.c4j.demo.security.demo.model.Principal;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.NamedPermission;
import org.apache.shiro.authz.annotation.RequiresUser;

import javax.annotation.security.PermitAll;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 *
 */
@Stateless
@PermitAll // Because we need to have access to verify the credentials
public class PermissionService {

    @EJB
    private InMemoryDatabase database;

    public Principal getPrincipalByUserName(String userName) {
        return database.getPrincipalByUserName(userName);
    }


    public List<NamedDomainPermission> getAllPermissions() {
        List<HRAppPermission> permissionList = database.getPermissionList();
        List<NamedDomainPermission> result = new ArrayList<NamedDomainPermission>();
        for (HRAppPermission permission : permissionList) {
            result.add(new NamedDomainPermission(permission.getName(), permission.getDomain(), permission.getActions(), permission.getTarget()));
        }
        return result;
    }

    public Collection<HRAppPermission> getPermissionsForPrincipal(UserPrincipal primaryPrincipal) {
        return database.getPermissions(primaryPrincipal.getId());
    }
}

