package com.skycrate.backend.skycrateBackend.controller;

import com.skycrate.backend.skycrateBackend.dto.LoginRequest;
import com.skycrate.backend.skycrateBackend.dto.LoginResponse;
import com.skycrate.backend.skycrateBackend.dto.RegisterUserDto;
import com.skycrate.backend.skycrateBackend.dto.TokenRefreshRequest;
import com.skycrate.backend.skycrateBackend.dto.TokenRefreshResponse;
import com.skycrate.backend.skycrateBackend.entity.RefreshToken;
import com.skycrate.backend.skycrateBackend.entity.User;
import com.skycrate.backend.skycrateBackend.repository.UserRepository;
import com.skycrate.backend.skycrateBackend.security.TokenBlacklistService;
import com.skycrate.backend.skycrateBackend.services.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(FileService.class);
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final RateLimiterService rateLimiterService;
    private final AuthenticationService authenticationService;

    public AuthController(
            AuthenticationManager authManager,
            JwtService jwtService,
            UserRepository userRepository,
            RefreshTokenService refreshTokenService,
            TokenBlacklistService tokenBlacklistService,
            RateLimiterService rateLimiterService,
            AuthenticationService authenticationService
    ) {
        this.authManager = authManager;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.rateLimiterService = rateLimiterService;
        this.authenticationService = authenticationService;
    }

    // New Register Endpoint
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterUserDto request) {
        User user = authenticationService.signUp(request);
        return ResponseEntity.ok("User registered successfully with username: " + user.getUsername());
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        String ip = servletRequest.getRemoteAddr();

        if (rateLimiterService.isBlocked(ip)) {
            return ResponseEntity.status(429).body("Too many login attempts. Please try again later.");
        }

        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
        } catch (Exception ex) {
            rateLimiterService.recordFailedAttempt(ip);
            return ResponseEntity.status(401).body("Invalid credentials.");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        rateLimiterService.resetAttempts(ip);

        String accessToken = jwtService.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken.getToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(7);
        String username = jwtService.extractUsername(token);

        userRepository.findByUsername(username).ifPresent(user -> {
            // Clear the cached decrypted private key for the user
            authenticationService.clearDecryptedPrivateKeyCache(user.getId().toString());

            // Delete the refresh token associated with the user
            refreshTokenService.logout(user); // This should delete the token
        });

        tokenBlacklistService.blacklistToken(token);

        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody TokenRefreshRequest request) {
        String requestToken = request.getRefreshToken();
        log.error("Received refresh token: " + requestToken);

        return refreshTokenService.findByToken(requestToken)
                .map(token -> {
                    if (refreshTokenService.isExpired(token)) {
                        log.error("Refresh token expired for user: " + token.getUser().getUsername());
                        // Clear the cached key on token expiry
                        authenticationService.clearDecryptedPrivateKeyCache(token.getUser().getId().toString());
                        return ResponseEntity.status(403).body("Refresh token expired");
                    }

                    User user = token.getUser();
                    String newAccessToken = jwtService.generateToken(user);
                    log.info("Generated new access token for user: " + user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken, requestToken));
                })
                .orElseGet(() -> {
                    log.error("Invalid refresh token: " + requestToken);
                    return ResponseEntity.status(403).body("Invalid refresh token");
                });
    }
}