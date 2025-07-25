package com.skycrate.backend.skycrateBackend.services;

import com.skycrate.backend.skycrateBackend.entity.RefreshToken;
import com.skycrate.backend.skycrateBackend.entity.User;
import com.skycrate.backend.skycrateBackend.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepo;

    @Value("${security.jwt.refresh-expiry-ms:86400000}")  //1 day in milliseconds
    private Long refreshTokenDurationMs;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepo) {
        this.refreshTokenRepo = refreshTokenRepo;
    }

//    @Transactional
//    public RefreshToken createRefreshToken(User user) {
//        refreshTokenRepo.deleteByUser(user);
//        refreshTokenRepo.flush();
//
//        RefreshToken token = new RefreshToken();
//        token.setUser(user);
//        token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
//        token.setToken(UUID.randomUUID().toString());
//        return refreshTokenRepo.save(token);
//    }

    @Transactional
    public RefreshToken createRefreshToken(User user) {
        refreshTokenRepo.deleteByUser(user);
        refreshTokenRepo.flush();

        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        token.setToken(UUID.randomUUID().toString());
        return refreshTokenRepo.save(token);
    }


    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepo.findByToken(token);
    }

    public boolean isExpired(RefreshToken token) {
        return token.getExpiryDate().isBefore(Instant.now());
    }
//
//    @Transactional
//    public void deleteByUser(User user) {
//        refreshTokenRepo.deleteByUser(user);
//    }

    @Transactional
    public void deleteByUser(User user) {
        try {
            refreshTokenRepo.deleteByUser(user);
            System.out.println("Successfully deleted refresh tokens for user: " + user.getId());
        } catch (Exception e) {
            System.err.println("Error deleting refresh tokens for user: " + user.getId() + " - " + e.getMessage());
        }
    }

    @Transactional
    public void logout(User user) {
        deleteByUser(user); // This should call the repository method to delete the token
    }

    public Optional<RefreshToken> refreshAccessToken(String refreshToken) {
        return findByToken(refreshToken).filter(token -> !isExpired(token));
    }
}