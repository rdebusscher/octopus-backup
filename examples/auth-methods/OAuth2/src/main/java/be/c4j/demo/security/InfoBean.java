package be.c4j.demo.security;

import be.c4j.ee.security.model.UserPrincipal;

import javax.annotation.PostConstruct;
import javax.enterprise.inject.Model;
import javax.inject.Inject;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@Model
public class InfoBean {

    @Inject
    private UserPrincipal userPrincipal;

    private List<Serializable> keys;

    @PostConstruct
    public void init() {
        keys = new ArrayList<Serializable>(userPrincipal.getInfo().keySet());
    }

    public String getInfoValue(String key) {
        return userPrincipal.getUserInfo(key);
    }

    public List<Serializable> getKeys() {
        return keys;
    }
}
