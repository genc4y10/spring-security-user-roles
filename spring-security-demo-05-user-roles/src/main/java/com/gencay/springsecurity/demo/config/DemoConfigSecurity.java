package com.gencay.springsecurity.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Configuration
@EnableWebSecurity
public class DemoConfigSecurity extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		UserBuilder users = User.withDefaultPasswordEncoder();

		auth.inMemoryAuthentication().withUser(users.username("gencay").password("gencay").roles("EMPLOYEE"));
		auth.inMemoryAuthentication().withUser(users.username("inci").password("inci").roles("EMPLOYEE","MANAGERS"));
		auth.inMemoryAuthentication().withUser(users.username("rukiye").password("rukiye").roles("EMPLOYEE","ADMIN"));
		auth.inMemoryAuthentication().withUser(users.username("nazli").password("nazli").roles("ADMIN,MANAGERS"));

	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests()
		.antMatchers("/").hasRole("EMPLOYEE")
		.antMatchers("/leaders/**").hasRole("MANAGERS")
		.antMatchers("/systems/**").hasRole("ADMIN")
				.and().formLogin().loginPage("/showMyLoginPage")
				.loginProcessingUrl("/authenticateTheUser").permitAll()
				.and().logout().permitAll()
				.and().exceptionHandling().accessDeniedPage("/access-denied");
	}

}
