package org.caringbridge.client.security.provider;

import org.caringbridge.client.security.services.BCryptUtility;
import org.caringbridge.client.security.services.ProfileUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component("authenticationProvider")
public class CBAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    private ProfileUserDetailsService userService;
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        UserDetails user = userService.loadUserByUsername(username);
        
        if (user == null) {
            throw new BadCredentialsException("Username not found.");
        }
 
        if (!BCryptUtility.authenticate(password, user.getPassword())) {
            throw new BadCredentialsException("Wrong password.");
        }

        return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
    }


    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
	    UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
	    throws AuthenticationException {
	return (UserDetails) authentication.getPrincipal();
    }

}
