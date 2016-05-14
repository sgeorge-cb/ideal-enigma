package org.caringbridge.client;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.caringbridge.client.security.provider.CBAuthenticationProvider;
import org.caringbridge.client.security.services.ProfileUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.mongo.embedded.EmbeddedMongoAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;


/**
 * Main class to run the application.
 * 
 * @author Simi George
 *
 */

@SpringBootApplication(exclude=EmbeddedMongoAutoConfiguration.class)
@ComponentScan("org.caringbridge.client")
@EnableOAuth2Client
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class CbWebApplication  extends WebSecurityConfigurerAdapter{

    @Autowired
    private ProfileUserDetailsService userService;
    
    /**
	 * Main method to run the Spring Boot Application.
	 * @param args arguments used when running on command line.
	 */
	public static void main(final String[] args) {
		System.setProperty("spring.devtools.livereload.enabled", "true");
		SpringApplication.run(CbWebApplication.class, args);
	}
	
	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}
	
	@Autowired
	@Qualifier("authenticationProvider")
	CBAuthenticationProvider authenticationProvider;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService);
		auth.authenticationProvider(authenticationProvider);
	}


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off	
		http
			.authorizeRequests()
				.antMatchers("/login", "/webjars/**", "/css/**").permitAll()
				.anyRequest().authenticated()
			.and()
			.formLogin().loginPage("/login")
			.defaultSuccessUrl("/goto/home")
			.loginProcessingUrl("/login")
			.failureUrl("/login?error")
			.usernameParameter("inputEmail")
			.passwordParameter("inputPassword")
			.and().rememberMe().tokenValiditySeconds(1209600)
			.key("my-rem-key")
			.rememberMeCookieName("rem-cookie")
			.rememberMeParameter("remember-me")
			.and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			.and().logout().permitAll()
			.logoutSuccessUrl("/login?logout").and().csrf()
			.and().csrf().csrfTokenRepository(csrfTokenRepository())
			.and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
			;

		// @formatter:on
	}
	
	private Filter csrfHeaderFilter() {
		return new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
					FilterChain filterChain) throws ServletException, IOException {
				CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
				if (csrf != null) {
					Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
					String token = csrf.getToken();
					if (cookie == null || token != null && !token.equals(cookie.getValue())) {
						cookie = new Cookie("XSRF-TOKEN", token);
						cookie.setPath("/");
						response.addCookie(cookie);
					}
				}
				filterChain.doFilter(request, response);
			}
		};
	}

	private CsrfTokenRepository csrfTokenRepository() {
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setHeaderName("X-XSRF-TOKEN");
		return repository;
	}
}



