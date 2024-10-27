package br.assistentediscente.authserver.configuration;

import br.assistentediscente.authserver.dto.APIResponse;
import br.assistentediscente.authserver.dto.LoginDTO;
import com.nimbusds.jose.shaded.gson.Gson;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Component
public class ADAuthenticationProvider implements AuthenticationProvider {

    @Value("${login-ad}")
    private String loginADUrl;

    public ADAuthenticationProvider() {
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String jsonRequest = prepareJsonForRequest(authentication);
        try {
            System.out.println("Disparando request para: " +loginADUrl);
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders header = new HttpHeaders();
            header.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<String> request = new HttpEntity<String>(jsonRequest, header);
            ResponseEntity<APIResponse> response =
                    restTemplate.postForEntity(loginADUrl, request, APIResponse.class);
            if (response.getStatusCode().value() == 200) {
                String institutionName = ((ADAuthenticationToken) authentication).getInstitutionName();
                return new ADAuthenticationToken(response.getBody().response(), response.getBody().response(), institutionName, List.of());
            }
            throw new BadCredentialsException("Bad Credentials");
        }catch (Throwable e) {
            throw new BadCredentialsException("Bad Credentials");
        }
    }

    private String prepareJsonForRequest(Authentication authentication){
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());
        String institutionName = ((ADAuthenticationToken) authentication).getInstitutionName();
        LoginDTO loginDTO  = new LoginDTO(username, password, institutionName.toUpperCase());
        Gson gson = new Gson();
        return gson.toJson(loginDTO);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }


}