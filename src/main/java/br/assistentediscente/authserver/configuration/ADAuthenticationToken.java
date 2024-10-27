package br.assistentediscente.authserver.configuration;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

public class ADAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private final String institutionName;
    public ADAuthenticationToken(Object principal, Object credentials, String institutionName) {
        super(principal, credentials);
        this.institutionName = institutionName;
        super.setAuthenticated(false);
    }

    public ADAuthenticationToken(Object principal, Object credentials, String institutionName,
                                 Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.institutionName = institutionName;
    }

    public String getInstitutionName() {
        return this.institutionName;
    }
}