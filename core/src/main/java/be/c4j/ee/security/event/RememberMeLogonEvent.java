package be.c4j.ee.security.event;

import org.apache.shiro.subject.Subject;

/**
 *
 */

public class RememberMeLogonEvent {


    private Subject subject;

    public RememberMeLogonEvent(Subject subject) {
        this.subject = subject;
    }

    public Subject getSubject() {
        return subject;
    }
}
