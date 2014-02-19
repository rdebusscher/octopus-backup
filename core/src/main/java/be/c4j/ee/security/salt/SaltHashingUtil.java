package be.c4j.ee.security.salt;

import be.c4j.ee.security.config.SecurityModuleConfig;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.SecureRandom;

@ApplicationScoped
public class SaltHashingUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(SaltHashingUtil.class);

    private int saltLength;

    @Inject
    private SecurityModuleConfig config;

    @PostConstruct
    public void init() {
        try {
            saltLength = Integer.valueOf(config.getSaltLength());
        } catch (NumberFormatException e) {
            LOGGER.warn("Salt length config parameter can't be converted to integer (value = " + config.getSaltLength()
                    + " 16 is taken as value");
        }
    }

    public byte[] nextSalt() {
        byte[] salt = new byte[saltLength];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(salt);
        return salt;
    }

    public String hash(String password, byte[] salt) {
        SimpleHash hash = new SimpleHash(config.getHashAlgorithmName(), password, salt);
        return hash.toHex();
    }

}
