package be.c4j.ee.security.sso.server.rest;

import be.c4j.ee.security.sso.OctopusSSOUser;

import java.util.Map;

/**
 *
 */
public interface RestUserInfoProvider {

    Map<String, String> defineInfo(OctopusSSOUser user);
}
