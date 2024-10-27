package br.assistentediscente.authserver.dto;

public record LoginDTO(String username,
                       String password,
                       String institutionName) {
}
