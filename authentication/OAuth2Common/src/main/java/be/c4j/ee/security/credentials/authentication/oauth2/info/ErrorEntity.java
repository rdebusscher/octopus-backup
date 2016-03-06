package be.c4j.ee.security.credentials.authentication.oauth2.info;

/**
 *
 */
public class ErrorEntity {

    private String text;

    public ErrorEntity(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }
}
