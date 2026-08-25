package co.simplon.springjwt.controller;

import co.simplon.springjwt.entity.dto.LoginDto;
import co.simplon.springjwt.service.TokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import co.simplon.springjwt.entity.UserEntity;
import co.simplon.springjwt.repository.UserRepository;

@RestController
@RequestMapping("auth")
public class AuthController {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public AuthController(
            PasswordEncoder passwordEncoderInjected,
            UserRepository userRepositoryInjected,
            AuthenticationManager authenticationManagerInjected,
            TokenService tokenServiceInjected) {
        this.passwordEncoder = passwordEncoderInjected;
        this.userRepository = userRepositoryInjected;
        this.authenticationManager = authenticationManagerInjected;
        this.tokenService = tokenServiceInjected;
    }

    @PostMapping("/login")
    public LoginDto login(@RequestBody UserEntity user) {

        Authentication auth = this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                user.getUsername(), user.getPassword()));
        String token = tokenService.generateToken(auth);
UserEntity userConnected = (UserEntity) auth.getPrincipal();
        return new LoginDto(token, userConnected.getUsername());
    }

    @PostMapping("/register")
    public UserEntity registerUser(@RequestBody UserEntity user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
}
