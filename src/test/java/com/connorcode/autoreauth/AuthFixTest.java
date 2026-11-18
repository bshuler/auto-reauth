package com.connorcode.autoreauth;

import com.connorcode.autoreauth.auth.AuthUtils;
import com.connorcode.autoreauth.auth.AuthUtils.AuthStatus;
import com.connorcode.autoreauth.auth.MicrosoftAuth;
import com.mojang.authlib.exceptions.AuthenticationException;
import com.mojang.authlib.exceptions.AuthenticationUnavailableException;
import com.mojang.authlib.exceptions.InvalidCredentialsException;
import com.mojang.authlib.exceptions.MinecraftClientHttpException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CompletionException;

import static org.junit.jupiter.api.Assertions.*;

class AuthFixTest {

    private static String jwtWithExp(long expEpochSeconds) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"exp\":" + expEpochSeconds + "}").getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }

    @Test
    void authStatusIsInvalidOnlyForInvalid() {
        assertFalse(AuthStatus.Unknown.isInvalid());
        assertFalse(AuthStatus.Online.isInvalid());
        assertFalse(AuthStatus.Offline.isInvalid());
        assertTrue(AuthStatus.Invalid.isInvalid());
    }

    @Test
    void accessTokenExpiryDetection() {
        long now = Instant.now().getEpochSecond();
        assertFalse(AuthUtils.isAccessTokenExpired(jwtWithExp(now + 3600)));
        assertTrue(AuthUtils.isAccessTokenExpired(jwtWithExp(now - 60)));
        assertTrue(AuthUtils.isAccessTokenExpired(""));
        assertTrue(AuthUtils.isAccessTokenExpired(null));
        assertFalse(AuthUtils.isAccessTokenExpired("opaque-non-jwt-token"));
    }

    @Test
    void transient503And429DoNotInvalidateValidToken() {
        String validJwt = jwtWithExp(Instant.now().getEpochSecond() + 3600);
        String expiredJwt = jwtWithExp(Instant.now().getEpochSecond() - 60);

        var http503 = new MinecraftClientHttpException(503);
        var unavailable503 = new AuthenticationUnavailableException("503", http503);
        assertEquals(AuthStatus.Online, AuthUtils.classifyAuthException(unavailable503, validJwt));
        assertEquals(AuthStatus.Invalid, AuthUtils.classifyAuthException(unavailable503, expiredJwt));

        var http429 = new MinecraftClientHttpException(429);
        var rateLimited = new AuthenticationException("429", http429);
        assertEquals(AuthStatus.Online, AuthUtils.classifyAuthException(rateLimited, validJwt));

        var bareUnavailable = new AuthenticationUnavailableException();
        assertEquals(AuthStatus.Online, AuthUtils.classifyAuthException(bareUnavailable, validJwt));
    }

    @Test
    void invalidCredentialsAnd401Or403AlwaysInvalidate() {
        String validJwt = jwtWithExp(Instant.now().getEpochSecond() + 3600);

        var invalidCreds = new InvalidCredentialsException("401", new MinecraftClientHttpException(401));
        assertEquals(AuthStatus.Invalid, AuthUtils.classifyAuthException(invalidCreds, validJwt));
        assertEquals(AuthStatus.Invalid, AuthUtils.classifyAuthException(new CompletionException(invalidCreds), validJwt));

        var forbidden = new AuthenticationException("403", new MinecraftClientHttpException(403));
        assertEquals(AuthStatus.Invalid, AuthUtils.classifyAuthException(forbidden, validJwt));
    }

    @Test
    void configAccountNbtSerializationHandlesClientId() {
        UUID uuid = UUID.fromString("0e5cfadf-3878-4b85-a8c4-e3ebf5934826");
        var defaultAcc = new Config.Account(new MicrosoftAuth.AccessToken("at1", "rt1"), uuid, "TheCritic");
        var defaultNbt = defaultAcc.serialize();
        assertTrue(defaultNbt.getString("client_id").isEmpty());
        var roundTripDefault = new Config.Account(defaultNbt);
        assertEquals(MicrosoftAuth.CLIENT_ID, roundTripDefault.clientId());

        String prismClientId = "c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb";
        var customAcc = new Config.Account(new MicrosoftAuth.AccessToken("at2", "rt2"), uuid, "TheCritic", prismClientId);
        var customNbt = customAcc.serialize();
        assertEquals(prismClientId, customNbt.getString("client_id").orElseThrow());
        var roundTripCustom = new Config.Account(customNbt);
        assertEquals(prismClientId, roundTripCustom.clientId());
        assertEquals("rt2", roundTripCustom.accessToken().refreshToken());
    }
}
