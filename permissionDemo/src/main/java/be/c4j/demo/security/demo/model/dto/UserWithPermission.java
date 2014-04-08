package be.c4j.demo.security.demo.model.dto;

/**
 * This class is here just for the demo purposes and not present in production systems. It is used to show the available users
 * on the login screen along with their permissions.
 */
public class UserWithPermission {

    private String userName;
    private String name;
    private String permissionInfo;

    public UserWithPermission(String userName, String name, String permissionInfo) {
        this.userName = userName;
        this.name = name;
        this.permissionInfo = permissionInfo;
    }

    public String getUserName() {
        return userName;
    }

    public String getPermissionInfo() {
        return permissionInfo;
    }

    public String getName() {
        return name;
    }
}
