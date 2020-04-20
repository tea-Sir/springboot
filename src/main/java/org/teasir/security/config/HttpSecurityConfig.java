package org.teasir.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/*
* 多个HttpSecurity请求
* */
@Configuration
//开启方法安全注解
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class HttpSecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder(){
        //BCryptPasswordEncoder 同样的密码编译后不一样

        return NoOpPasswordEncoder.getInstance();
    }

    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("jx").password("111").roles("admin")
                .and().withUser("wh").password("222").roles("user");
    }

    @Configuration
    @Order(1)
    public static class AdminSecurityConfig extends WebSecurityConfigurerAdapter{
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/admin/**").authorizeRequests().anyRequest().hasRole("admin");
        }
    }

    @Configuration
    public static class otherSecurityConfig extends WebSecurityConfigurerAdapter{
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().authenticated()
                    .and()
                    .formLogin()
                    .usernameParameter("usernm")
                    .passwordParameter("passwd")
                    .loginProcessingUrl("/doLogin")
                    .permitAll()
                    .and()
                    .csrf()
                    .disable();
        }
    }
}
