package be.c4j.ee.security.credentials.authentication.oauth2.csrf;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 */
@ApplicationScoped
public class CSRFTokenProducer {

    private SecureRandom random;

    @PostConstruct
    public void init() {
        random = new SecureRandom();
    }

    public String nextToken() {
        return new BigInteger(130, random).toString(32);
    }
}
