package org.teasir.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class HelloService {
    //方法安全注解，接口可访问，但安全注解的方法需要角色才能访问
    
    @PreAuthorize("hasRole('admin')")
    public String admin(){
        return "admin";
    }

    @Secured("ROLE_admin")
    public String user1(){
        return "user1";
    }

    @PreAuthorize("hasAnyRole('admin','user')")
    public String user2(){
        return "user2";
    }
}
