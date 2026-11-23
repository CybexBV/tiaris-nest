# The Nest's web server (`services.nginx`). Boot scripts, the boot context
# and every other request go to the daemon. For a binary-cache member or a
# workstation runtime file the daemon checks the request (path, bundle
# authorization, range) and answers with `X-Accel-Redirect` to one of the
# internal /_tiaris/ locations below; nginx then sends the file itself
# (src/assets.rs, `hand_file`). A direct request never reaches those
# locations, and each takes only the exact names the daemon hands over.
{ pxeMenu }:
let
  daemon = "http://127.0.0.1:8080";
  # Nix base32: 0-9 and a-z without e, o, t and u.
  base32 = "[0-9a-df-np-sv-z]";
  # Content-Type and Cache-Control come from the daemon's answer (nginx keeps
  # them on X-Accel-Redirect); the security headers are set here.
  handedFile = ''
    internal;
    disable_symlinks on;
    sendfile on;
    tcp_nopush on;
    etag off;
    if_modified_since off;
    max_ranges 1;
    add_header X-Content-Type-Options "nosniff";
  '';
in {
  enable = true;
  defaultListenAddresses = [ "0.0.0.0" ];
  virtualHosts."_" = {
    default = true;
    # The daemon tells a computer from the Nest's own readiness check by
    # this address (src/routes/mod.rs, `is_own_request`); it replaces
    # whatever the client sent. With the client's port the daemon counts a
    # download nginx sends for it until that connection closes
    # (src/activity.rs).
    extraConfig = ''
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_set_header X-Tiaris-Client-Port $remote_port;
    '';
    locations."/".proxyPass = daemon;
    locations."~ \"^/boot-session/[A-Za-z0-9_-]{22}/context\\.cpio$\"" = { proxyPass = daemon; extraConfig = "access_log off;"; };
    locations."= /files/assets/pxe-menu.png".alias = pxeMenu;
    locations."~ \"^/manage-source/(?<source_file>[0-9a-f]{40}\\.(?:tar|json))$\"" = { alias = "/usr/share/tiaris-nest/manage-source/$source_file"; extraConfig = ''
      autoindex off;
      disable_symlinks on;
      limit_except GET { deny all; }
      add_header Cache-Control "public, max-age=31536000, immutable";
      add_header X-Content-Type-Options "nosniff";
    ''; };
    locations."/assets/" = { alias = "/var/cache/tiaris-nest/www/assets/"; extraConfig = "autoindex off;"; };
    # cache.root_dir and paths.boot_assets_dir of an installed Nest
    # (src/provisioning/storage.rs).
    locations."~ \"^/_tiaris/cache/(?<cache_file>${base32}{32}\\.narinfo|nix-cache-info|nar/${base32}{52}\\.nar(?:\\.(?:xz|bz2|zst|gz|lzip|lz4|br))?)$\"" = {
      alias = "/var/cache/tiaris-nest/www/cache/$cache_file";
      extraConfig = handedFile;
    };
    # The installer checks this exact ETag (Tiaris agent, installer_kexec.rs).
    locations."~ \"^/_tiaris/netboot/(?<bundle>[0-9a-f]{64})/(?<component>bzImage|initrd|nix-store\\.squashfs)$\"" = {
      alias = "/var/cache/tiaris-nest/www/netboot/$bundle/$component";
      extraConfig = handedFile + ''
        add_header ETag "\"$bundle-$component\"";
      '';
    };
  };
}
