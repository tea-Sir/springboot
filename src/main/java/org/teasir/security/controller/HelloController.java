package org.teasir.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.teasir.security.service.HelloService;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/admin/hello")
    public String aHello() {
        return "admin hello";
    }

    @GetMapping("/user/hello")
    public String uHello() {
        return "user hello";
    }

    @GetMapping("/login")
    public String login() {
        return "please login";
    }


    @Autowired
    HelloService helloService;
    @GetMapping("/admin1")
    public String admin1(){
        return helloService.admin();
    }

    @GetMapping("/user1")
    public String user1(){
        return helloService.user1();
    }

    @GetMapping("/user2")
    public String user2(){
        return helloService.user2();
    }
}