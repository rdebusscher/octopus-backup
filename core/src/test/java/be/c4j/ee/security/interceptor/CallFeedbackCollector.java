package be.c4j.ee.security.interceptor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 */
public final class CallFeedbackCollector {

    private static Set<String> calledMethods = new HashSet<String>();

    private CallFeedbackCollector() {
    }

    public static void addCallFeedback(String calledMethod) {
        calledMethods.add(calledMethod);
    }

    public static void reset() {
        calledMethods.clear();
    }

    public static List<String> getCallFeedback() {
        return new ArrayList<String>(calledMethods);
    }
}
