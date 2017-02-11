package be.c4j.ee.security.url;

import java.util.Map;

/**
 *
 */

public interface ProgrammaticURLProtectionProvider {


    Map<String, String> getURLEntriesToAdd();
}
