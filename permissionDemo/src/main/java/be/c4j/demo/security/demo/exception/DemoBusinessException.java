package be.c4j.demo.security.demo.exception;

/**
 *
 */
public abstract class DemoBusinessException extends RuntimeException {
    @Override
    public String getMessage() {
        return getMessageKey();
    }

    abstract String getMessageKey();
}
