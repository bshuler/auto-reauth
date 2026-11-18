package com.connorcode.autoreauth.auth;

import com.google.gson.JsonParser;
import com.mojang.authlib.exceptions.AuthenticationException;
import com.mojang.authlib.exceptions.AuthenticationUnavailableException;
import com.mojang.authlib.exceptions.InvalidCredentialsException;
import com.mojang.authlib.exceptions.MinecraftClientHttpException;
import com.mojang.authlib.minecraft.UserApiService;
import com.mojang.authlib.services.MinecraftServicesDiscoveryService;
import com.mojang.realmsclient.RealmsAvailability;
import com.mojang.realmsclient.client.RealmsClient;
import com.mojang.realmsclient.gui.RealmsDataFetcher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import net.minecraft.client.User;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.client.gui.screens.social.PlayerSocialManager;
import net.minecraft.client.multiplayer.ProfileKeyPairManager;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.chat.report.ReportEnvironment;
import net.minecraft.client.multiplayer.chat.report.ReportingContext;
import net.minecraft.client.multiplayer.resolver.ServerAddress;
import net.minecraft.client.quickplay.QuickPlay;
import net.minecraft.client.quickplay.QuickPlayLog;
import net.minecraft.network.chat.CommonComponents;

import static com.connorcode.autoreauth.Main.*;

public class AuthUtils {
    private static final long TRANSIENT_RETRY_DELAY_MS = 1500L;

    public static CompletableFuture<AuthStatus> getAuthStatus() {
        log.info("Checking auth status");
        return CompletableFuture.supplyAsync(() -> {
            var session = client.getUser();
            var token = session.getAccessToken();
            var id = UUID.randomUUID().toString();

            // Thank you https://github.com/axieum/authme
            var sessionService = client.services().sessionService();
            for (int attempt = 0; attempt < 2; attempt++) {
                try {
                    sessionService.joinServer(client.getUser().getProfileId(), token, id);
                    var authStatus = sessionService.hasJoinedServer(session.getName(), id, null) != null ? AuthStatus.Online : AuthStatus.Offline;
                    if (authStatus.isOnline()) sentToast = false;
                    log.info("Auth status: " + authStatus.getText());
                    return authStatus;
                } catch (AuthenticationException e) {
                    if (attempt == 0 && isTransientAuthException(e)) {
                        log.warn("Transient auth check error, retrying in {}ms: {}", TRANSIENT_RETRY_DELAY_MS, e.toString());
                        try {
                            Thread.sleep(TRANSIENT_RETRY_DELAY_MS);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            return classifyAuthException(e, token);
                        }
                        continue;
                    }
                    var status = classifyAuthException(e, token);
                    if (status.isOnline()) {
                        sentToast = false;
                        log.warn("Auth server unavailable ({}); cached token has not expired, keeping Online status", e.toString());
                    } else {
                        log.info("Auth check failed ({}): {}", status.getText(), e.toString());
                    }
                    return status;
                }
            }
            return AuthStatus.Offline;
        });
    }

    /**
     * Classifies an authentication check failure so transient session-server
     * outages (HTTP 503/429 or I/O errors) do not falsely invalidate a still-valid token.
     */
    public static AuthStatus classifyAuthException(Throwable e, String token) {
        Throwable current = unwrapCompletionException(e);
        if (current instanceof InvalidCredentialsException) {
            return AuthStatus.Invalid;
        }
        MinecraftClientHttpException httpEx = findHttpException(current);
        if (httpEx != null) {
            int status = httpEx.getStatus();
            if (status == 401 || status == 403) {
                return AuthStatus.Invalid;
            }
            if (status >= 500 || status == 429) {
                return isAccessTokenExpired(token) ? AuthStatus.Invalid : AuthStatus.Online;
            }
        }
        if (current instanceof AuthenticationUnavailableException) {
            return isAccessTokenExpired(token) ? AuthStatus.Invalid : AuthStatus.Online;
        }
        return isAccessTokenExpired(token) ? AuthStatus.Invalid : AuthStatus.Offline;
    }

    static boolean isTransientAuthException(Throwable e) {
        Throwable current = unwrapCompletionException(e);
        if (current instanceof InvalidCredentialsException) {
            return false;
        }
        MinecraftClientHttpException httpEx = findHttpException(current);
        if (httpEx != null) {
            int status = httpEx.getStatus();
            if (status == 401 || status == 403) {
                return false;
            }
            return status >= 500 || status == 429;
        }
        return current instanceof AuthenticationUnavailableException || current instanceof IOException;
    }

    private static Throwable unwrapCompletionException(Throwable e) {
        Throwable current = e;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static MinecraftClientHttpException findHttpException(Throwable e) {
        Throwable current = e;
        while (current != null) {
            if (current instanceof MinecraftClientHttpException httpEx) {
                return httpEx;
            }
            current = current.getCause();
        }
        return null;
    }

    /**
     * Checks whether a Minecraft JWT access token is missing or past its {@code exp} claim.
     * Unparseable or opaque tokens are treated as non-expired so transient outages do not lock out custom auth.
     */
    public static boolean isAccessTokenExpired(String token) {
        if (token == null || token.isBlank()) {
            return true;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
            var payload = JsonParser.parseString(new String(decoded, StandardCharsets.UTF_8)).getAsJsonObject();
            if (!payload.has("exp") || !payload.get("exp").isJsonPrimitive()) {
                return false;
            }
            long exp = payload.get("exp").getAsLong();
            return exp <= Instant.now().getEpochSecond() + 30L;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    public static void setSession(User session) throws AuthenticationException {
        log.info("Overwriting session with {} ({})", session.getName(), session.getProfileId());
        client.user = session;
        boolean isDeveloperMode = client.isOfflineDeveloperMode();
        String accessToken = session.getAccessToken();
        MinecraftServicesDiscoveryService discoveryService = MinecraftServicesDiscoveryService.create(client.getProxy(), !isDeveloperMode);
        client.userApiService = isDeveloperMode ? UserApiService.OFFLINE : discoveryService.createUserApiService(accessToken);
        client.playerSocialManager = new PlayerSocialManager(client, client.userApiService, discoveryService.createFriendsService(accessToken), client.remoteFriendListUpdateHandler);
        client.profileKeyPairManager = ProfileKeyPairManager.create(client.userApiService, session, client.gameDirectory.toPath());
        client.reportingContext = ReportingContext.create(client.reportingContext.environment, client.userApiService);
        RealmsAvailability.future = null;

        var realmsClient = new RealmsClient(session.getSessionId(), session.getName(), client);
        RealmsClient.realmsClientInstance = realmsClient;
        client.realmsDataFetcher = new RealmsDataFetcher(realmsClient);
    }

    public static void connectToServer(ServerAddress address, ServerData info, boolean quickPlay) {
        var connectScreen = new ConnectScreen(new TitleScreen(), quickPlay ? QuickPlay.ERROR_TITLE : CommonComponents.CONNECT_FAILED);
        client.disconnect(connectScreen, false);
        client.prepareForMultiplayer();
        client.updateReportEnvironment(ReportEnvironment.thirdParty(info != null ? info.ip : address.getHost()));
        if (info != null) {
            client.quickPlayLog().setWorldData(QuickPlayLog.Type.MULTIPLAYER, info.ip, info.name);
        }
        client.gui.setScreen(connectScreen);
        connectScreen.connect(client, address, info, null);
    }

    public enum AuthStatus {
        Unknown, Invalid, Online, Offline;

        public String getText() {
            return switch (this) {
                case Unknown -> "Waiting...";
                case Invalid -> "Invalid";
                case Online -> "Online";
                case Offline -> "Offline";
            };
        }

        public boolean isInvalid() {
            return this == Invalid;
        }

        public boolean isOnline() {
            return this == Online;
        }
    }
}
