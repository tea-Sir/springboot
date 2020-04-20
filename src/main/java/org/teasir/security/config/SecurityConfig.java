package org.teasir.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.security.auth.login.CredentialException;
import javax.security.auth.login.CredentialExpiredException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){
        return  NoOpPasswordEncoder.getInstance();
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("jx").password("123").roles("admin")
                .and().withUser("wh").password("123").roles("user");
    }

   @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasAnyRole("admin","user")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/doLogin")
                //.loginPage("/login")
                .usernameParameter("usernm")
                .passwordParameter("passwd")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        resp.setContentType("application/json;charset:utf-8");
                       PrintWriter out= resp.getWriter();
                        Map<String,Object> map=new HashMap();
                        map.put("statu",200);
                        map.put("msg",authentication.getPrincipal());
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException e) throws IOException, ServletException {
                        resp.setContentType("application/json;charset:utf-8");
                        PrintWriter out=resp.getWriter();
                        Map<String,Object> map=new HashMap<>();
                        map.put("status",401);
                        if(e instanceof LockedException){
                            map.put("msg","账号被锁定，登录失败！");
                        }else if(e instanceof BadCredentialsException){
                            map.put("msg","用户名或密码错误，登录失败！");
                        }else if(e instanceof DisabledException){
                            map.put("msg","账号被禁用，登录失败！");
                        }else if(e instanceof AccountExpiredException){
                            map.put("msg","账号过期，登录失败！");
                        }else if(e instanceof CredentialsExpiredException){
                            map.put("msg","密码过期，登录失败！");
                        }else{
                            map.put("msg","登录失败！");
                        }
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                //允许所有的验证
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/loginout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out=resp.getWriter();
                        Map<String,Object> map=new HashMap<>();
                        map.put("status",200);
                        map.put("msg","注销成功！");
                        //new ObjectMapper().writeValueAsString(map)将对象转化为json
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();

                    }
                })
                .and()
                .csrf().disable();
    }
}
