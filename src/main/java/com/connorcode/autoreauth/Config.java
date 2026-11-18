package com.connorcode.autoreauth;

import com.connorcode.autoreauth.auth.MicrosoftAuth;
import net.minecraft.client.User;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.ListTag;
import net.minecraft.nbt.NbtIo;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Optional;
import java.util.UUID;

import static com.connorcode.autoreauth.Main.directory;

public class Config {
    private static final Path CONFIG_PATH = directory.resolve("config.nbt");

    public boolean debug = false;
    public boolean auto = true;
    public Account defaultAccount = null;
    public ArrayList<Account> accounts = new ArrayList<>();

    public Config() {
    }

    public synchronized void addAccount(Account account) {
        for (int i = 0; i < accounts.size(); i++) {
            if (accounts.get(i).uuid.equals(account.uuid)) {
                accounts.set(i, account);
                return;
            }
        }

        accounts.add(account);
    }

    public synchronized void removeAccount(Account account) {
        if (account.equals(defaultAccount)) defaultAccount = null;
        accounts.removeIf(a -> a.equals(account));
    }

    public synchronized Optional<Account> getAccount(UUID uuid) {
        for (var account : accounts)
            if (account.uuid.equals(uuid)) return Optional.of(account);
        if (defaultAccount != null) return Optional.of(defaultAccount);
        if (!accounts.isEmpty()) return Optional.of(accounts.getFirst());
        return Optional.empty();
    }

    public synchronized boolean isDefault(Config.Account account) {
        return this.defaultAccount == null ? (!this.accounts.isEmpty() && this.accounts.getFirst()
                .equals(account)) : this.defaultAccount.equals(account);
    }

    public synchronized boolean load() {
        return load(CONFIG_PATH);
    }

    public synchronized boolean load(Path path) {
        if (Files.notExists(path)) return false;

        try {
            var tag = NbtIo.read(path);
            assert tag != null;

            this.debug = tag.getBoolean("debug").orElse(false);
            this.auto = tag.getBoolean("auto").orElse(true);
            this.accounts = tag.getList("accounts").orElse(new ListTag()).stream()
                    .map(account -> new Account(account.asCompound().orElseThrow()))
                    .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);

            int defaultIdx = tag.getInt("default").orElse(-1);
            this.defaultAccount = defaultIdx >= 0 && defaultIdx < accounts.size() ? this.accounts.get(defaultIdx) : null;

            return true;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public synchronized void save() {
        save(CONFIG_PATH);
    }

    public synchronized void save(Path path) {
        var tag = new CompoundTag();
        tag.putBoolean("debug", debug);
        tag.putBoolean("auto", auto);
        tag.putInt("default", accounts.indexOf(defaultAccount));

        var accounts = new ListTag();
        for (var account : this.accounts)
            accounts.add(account.serialize());

        tag.put("accounts", accounts);

        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            NbtIo.write(tag, path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public record Account(MicrosoftAuth.AccessToken accessToken, UUID uuid, String username, String clientId) {
        public Account(MicrosoftAuth.AccessToken accessToken, UUID uuid, String username) {
            this(accessToken, uuid, username, MicrosoftAuth.CLIENT_ID);
        }

        public Account(MicrosoftAuth.AccessToken access, User session) {
            this(access, session, MicrosoftAuth.CLIENT_ID);
        }

        public Account(MicrosoftAuth.AccessToken access, User session, String clientId) {
            this(access, session.getProfileId(), session.getName(), normalizeClientId(clientId));
        }

        public Account(CompoundTag nbt) {
            this(
                new MicrosoftAuth.AccessToken(
                    nbt.getString("accessToken").orElseThrow(),
                    nbt.getString("refreshToken").orElseThrow()
                ),
                Misc.parseUUID(nbt.getString("uuid").orElseThrow()),
                nbt.getString("username").orElseThrow(),
                normalizeClientId(nbt.getString("client_id").orElse(null))
            );
        }

        private static String normalizeClientId(String clientId) {
            return (clientId == null || clientId.isBlank()) ? MicrosoftAuth.CLIENT_ID : clientId;
        }

        public CompoundTag serialize() {
            var tag = new CompoundTag();
            tag.putString("accessToken", accessToken.accessToken());
            tag.putString("refreshToken", accessToken.refreshToken());
            tag.putString("uuid", uuid.toString());
            tag.putString("username", username);
            var effectiveClientId = normalizeClientId(clientId);
            if (!effectiveClientId.equals(MicrosoftAuth.CLIENT_ID)) {
                tag.putString("client_id", effectiveClientId);
            }
            return tag;
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof Account account && this.uuid.equals(account.uuid);
        }
    }
}
