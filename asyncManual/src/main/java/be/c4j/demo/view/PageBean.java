package be.c4j.demo.view;

import be.c4j.demo.DemoService;

import javax.enterprise.inject.Model;
import javax.inject.Inject;

/**
 *
 */
@Model
public class PageBean {

    @Inject
    private DemoService demoService;

    private String text;

    public void testAsync() {
        text = demoService.sayHello();
    }

    public String getText() {
        return text;
    }
}
