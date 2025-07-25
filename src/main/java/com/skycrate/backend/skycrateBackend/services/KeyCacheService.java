package com.skycrate.backend.skycrateBackend.services;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class KeyCacheService {

    private final ConcurrentHashMap<Long, String> keyCache = new ConcurrentHashMap<>();

    public void cacheKey(Long userId, String decryptedKey) {
        keyCache.put(userId, decryptedKey);
    }

    public String getKey(Long userId) {
        return keyCache.get(userId);
    }

    public void clearKey(Long userId) {
        keyCache.remove(userId);
    }

    public void clearAllKeys() {
        keyCache.clear();
    }
}

