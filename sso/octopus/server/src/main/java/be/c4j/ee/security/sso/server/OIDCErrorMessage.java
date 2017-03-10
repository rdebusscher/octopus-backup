package be.c4j.ee.security.sso.server;

/**
 *
 */

public enum OIDCErrorMessage {

    AUTHENTICATE_UNKNOWN_CLIENT_ID("OCT-OIDC-011", "Invalid client_id"),
    AUTHENTICATE_UNKNOWN_REDIRECT_URI("OCT-OIDC-012", "Invalid redirect_uri");

    private String code;
    private String message;

    OIDCErrorMessage(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
