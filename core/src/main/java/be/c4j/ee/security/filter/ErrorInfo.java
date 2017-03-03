package be.c4j.ee.security.filter;

/**
 *
 */

public class ErrorInfo {


    private String code;
    private String message;

    // For JAX-RS
    public ErrorInfo() {
    }

    public ErrorInfo(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public String toJSON() {
        // We don't have a JSON processor here. So if this is the only place where we need it, just use String concatenation.
        return "{\"code\":\"" + code + "\", \"message\":\"" + message + "\"}";
    }
}
