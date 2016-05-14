package org.caringbridge.client.security.services;


import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.caringbridge.client.security.model.Profile;
import org.caringbridge.client.security.repository.ProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("userDetailsService")
public class ProfileUserDetailsService implements UserDetailsService{
    
    @Autowired
    ProfileRepository profileRepository;
    
    public Profile authenticate(String userId, String password) {
        List<Profile> profiles = profileRepository.findByEmailAddress(userId);
        if (profiles.isEmpty()) {
            throw new UsernameNotFoundException(String.format("Username %s not found.", userId));
        } else if (profiles.size()>1) {
            throw new BadCredentialsException(String.format("Invalid credentials for username %s.", userId));
        }
        Profile userProfile = profiles.get(0);

        if (!BCryptUtility.authenticate(password, userProfile.getPassword())) {
              throw new BadCredentialsException("Invalid password.");
        }
    	return userProfile;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        List<Profile> profiles = profileRepository.findByEmailAddress(username);
        if (!profiles.isEmpty() && profiles.size()==1) {
            Profile userProfile = profiles.get(0);
            Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));//get from db
            CBUserDetails user = new CBUserDetails(userProfile.getEmail().getAddress(), userProfile.getPassword(), 
    		    true, true, true,  userProfile.getFailedLoginAttempts()<5,authorities);
    	    user.setFirstName(userProfile.getFirstName());
    	    user.setLastName(userProfile.getLastName());
    	    user.setProfileId(userProfile.getProfileId());
    	    return user;
        }
	return null;
    }

}
