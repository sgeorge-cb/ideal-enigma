package org.caringbridge.client.controllers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.caringbridge.client.security.services.SAMLService;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class IndexController {

	@Autowired
	SAMLService samlService;

    @RequestMapping(value={"/home"},method={RequestMethod.GET})
    public String home() {
        return "home";
    }
    
    @RequestMapping(value={"", "/", "/login","/error"},method={RequestMethod.GET})
    public String login() {
        return "login";
    }

    @RequestMapping(value={"/goto/{pageName}"},method={RequestMethod.GET})
    public String goToPage(@PathVariable(value="pageName") final String pageName) {
        return pageName;
    }

    @RequestMapping(value="/saml",method=RequestMethod.GET,produces="text/html")
    public String redirect(Model model) {
    	try {
    		//We are hardcoding the sp url
    		model.addAttribute("spPostUrl", SAMLService.SP_ENDPOINT);
    		model.addAttribute("relayState", Math.random());
    		model.addAttribute("sAMLResponse",samlService.getSamlResponse(
    				SecurityContextHolder.getContext().getAuthentication().getName(),null,null));
        	return "saml";
    	} catch (Exception e) {
			e.printStackTrace();
		} 
    	return "error";
    }

    @RequestMapping(value="/sso/saml",method=RequestMethod.GET)
    public String a(@RequestParam("SAMLRequest") String samlRequest,
    		@RequestParam(value="RelayState", required = false) String relayState, 
    		Model model) throws Exception {
    	AuthnRequest request = samlService.decodeSamlRequest(samlRequest);
   		model.addAttribute("spPostUrl", request.getAssertionConsumerServiceURL());
		model.addAttribute("relayState", relayState);
   		model.addAttribute("sAMLResponse", samlService.getSamlResponse(
				SecurityContextHolder.getContext().getAuthentication().getName(), 
				request.getID(), request.getAssertionConsumerServiceURL()));

    	return "saml";
    }
    
    @RequestMapping(value="/logout", method = RequestMethod.GET)
    public String logoutPage (HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null){    
            new SecurityContextLogoutHandler().logout(request, response, auth);
            new CookieClearingLogoutHandler("JSESSIONID","rem-cookie").logout(request, response, auth);
        }
        return "redirect:/login?logout";
    }

}
