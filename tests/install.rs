// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Installer tests against a temporary root with a fake system.

use afas_entra_sync::config::Config;
use afas_entra_sync::install::{
    Answers, InstallOptions, ModuleSetupOptions, SetupModule, System, UninstallOptions,
    build_config, install, module_setup, new_certificate, thumbprint, uninstall, unit_files,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const TENANT: &str = "11111111-2222-3333-4444-555555555555";
const CLIENT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const SP: &str = "99999999-8888-7777-6666-555555555555";
const JOB: &str = "API2AD.0123456789abcdef0123456789abcdef.11111111-2222-3333-4444-555555555555";

#[derive(Default)]
struct Fake {
    root: bool,
    systemd: bool,
    tty: bool,
    user: RefCell<bool>,
    inputs: RefCell<VecDeque<String>>,
    ran: RefCell<Vec<String>>,
    said: RefCell<Vec<String>>,
    chowned: RefCell<Vec<(PathBuf, u32)>>,
}

impl Fake {
    fn new() -> Self {
        Fake {
            root: true,
            systemd: true,
            ..Default::default()
        }
    }
    fn ran(&self) -> Vec<String> {
        self.ran.borrow().clone()
    }
}

impl System for Fake {
    fn is_root(&self) -> bool {
        self.root
    }
    fn has_systemd(&self) -> bool {
        self.systemd
    }
    fn user_ids(&self, _: &str) -> Option<(u32, u32)> {
        self.user.borrow().then_some((990, 990))
    }
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
        self.ran
            .borrow_mut()
            .push(format!("{program} {}", args.join(" ")));
        if program == "useradd" {
            *self.user.borrow_mut() = true;
        }
        if program == "userdel" {
            *self.user.borrow_mut() = false;
        }
        Ok(())
    }
    fn chown(&self, path: &Path, uid: u32, _: u32) -> Result<(), String> {
        self.chowned.borrow_mut().push((path.to_path_buf(), uid));
        Ok(())
    }
    fn interactive(&self) -> bool {
        self.tty
    }
    fn prompt(&self, _: &str, _: bool) -> Result<String, String> {
        self.inputs
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| "no more input".to_string())
    }
    fn say(&self, line: &str) {
        self.said.borrow_mut().push(line.to_string());
    }
}

fn answers() -> Answers {
    Answers {
        afas_env: Some("12345".into()),
        connector: None,
        tenant_id: Some(TENANT.into()),
        client_id: Some(CLIENT.into()),
        service_principal_id: Some(SP.into()),
        job_id: Some(JOB.into()),
        upn_domains: vec!["Example.com".into()],
        employee_count: Some(600),
        token: Some("ABCDEF0123456789".into()),
    }
}

struct Env {
    dir: tempfile::TempDir,
    bin: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("dist-binary");
        std::fs::write(&bin, b"binary v1").unwrap();
        Env { dir, bin }
    }
    fn root(&self) -> PathBuf {
        self.dir.path().join("root")
    }
    fn f(&self, abs: &str) -> PathBuf {
        self.root().join(abs.trim_start_matches('/'))
    }
    fn opts(&self) -> InstallOptions {
        InstallOptions {
            root: self.root(),
            binary: self.bin.clone(),
            answers: answers(),
            reconfigure: false,
            replace_token: false,
            renew_cert: false,
            enable_sync: false,
            gui: false,
        }
    }
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn fresh_install_creates_everything_with_safe_permissions() {
    let e = Env::new();
    let sys = Fake::new();
    let out = install(&sys, &e.opts()).unwrap();
    assert!(out.user_created && out.binary_updated && out.config_written);
    assert!(out.token_written && out.cert_created && out.units_written);
    assert!(!out.sync_enabled);
    assert!(sys.ran()[0].starts_with("useradd --system"));
    assert_eq!(mode(&e.f("/etc/afas-entra-sync")), 0o700);
    assert_eq!(mode(&e.f("/var/lib/afas-entra-sync")), 0o700);
    assert_eq!(mode(&e.f("/etc/afas-entra-sync/config.toml")), 0o600);
    assert_eq!(mode(&e.f("/etc/afas-entra-sync/afas.token")), 0o600);
    assert_eq!(mode(&e.f("/etc/afas-entra-sync/key.pem")), 0o600);
    assert_eq!(mode(&e.f("/etc/afas-entra-sync/cert.pem")), 0o644);
    assert_eq!(mode(&e.f("/usr/local/bin/afas-entra-sync")), 0o755);
    assert_eq!(
        std::fs::read(e.f("/usr/local/bin/afas-entra-sync")).unwrap(),
        b"binary v1"
    );
    // Secrets and config owned by the service user, binary by root.
    let owned = sys.chowned.borrow();
    for f in ["config.toml", "afas.token", "key.pem", "cert.pem"] {
        let p = e.f(&format!("/etc/afas-entra-sync/{f}"));
        assert!(owned.iter().any(|(q, u)| *q == p && *u == 990), "{f}");
    }
    assert!(
        owned
            .iter()
            .any(|(q, u)| *q == e.f("/usr/local/bin/afas-entra-sync") && *u == 0)
    );
    // Config is valid and holds the answers.
    let c =
        Config::parse(&std::fs::read_to_string(e.f("/etc/afas-entra-sync/config.toml")).unwrap())
            .unwrap();
    assert_eq!(
        c.afas.base_url,
        "https://12345.rest.afas.online/ProfitRestServices"
    );
    assert_eq!(c.afas.connector, "Entra_Medewerkers");
    assert_eq!(
        c.afas.token_file.as_deref(),
        Some(Path::new("/etc/afas-entra-sync/afas.token"))
    );
    assert!(c.afas.token_env.is_none());
    assert_eq!(c.entra.tenant_id, TENANT);
    assert_eq!(c.entra.job_id, JOB);
    assert_eq!(c.policy.allowed_upn_domains, vec!["example.com"]);
    assert_eq!(c.policy.min_records, 540);
    assert!(!c.gui.enabled);
    // Units written, daemon reloaded, timers not enabled yet.
    for u in [
        "afas-entra-sync.service",
        "afas-entra-sync.timer",
        "afas-entra-sync-check-logs.service",
        "afas-entra-sync-check-logs.timer",
    ] {
        assert!(e.f(&format!("/etc/systemd/system/{u}")).exists(), "{u}");
    }
    assert!(
        !e.f("/etc/systemd/system/afas-entra-sync-gui.service")
            .exists()
    );
    assert!(sys.ran().contains(&"systemctl daemon-reload".to_string()));
    assert!(!sys.ran().iter().any(|r| r.contains("enable --now")));
    // Thumbprint printed for Entra.
    let tp = out.cert_thumbprint.unwrap();
    assert_eq!(tp.len(), 40);
    assert!(sys.said.borrow().iter().any(|l| l.contains(&tp)));
}

#[test]
fn second_run_keeps_config_token_and_certificate() {
    let e = Env::new();
    install(&Fake::new(), &e.opts()).unwrap();
    let cfg = std::fs::read(e.f("/etc/afas-entra-sync/config.toml")).unwrap();
    let key = std::fs::read(e.f("/etc/afas-entra-sync/key.pem")).unwrap();
    let sys = Fake::new();
    *sys.user.borrow_mut() = true;
    let mut o = e.opts();
    o.answers = Answers::default(); // nothing needed on a re-run
    let out = install(&sys, &o).unwrap();
    assert!(!out.user_created && !out.binary_updated && !out.config_written);
    assert!(!out.token_written && !out.cert_created);
    assert_eq!(
        std::fs::read(e.f("/etc/afas-entra-sync/config.toml")).unwrap(),
        cfg
    );
    assert_eq!(
        std::fs::read(e.f("/etc/afas-entra-sync/key.pem")).unwrap(),
        key
    );
    assert!(!sys.ran().iter().any(|r| r.starts_with("useradd")));
}

#[test]
fn upgrade_replaces_only_the_binary() {
    let e = Env::new();
    install(&Fake::new(), &e.opts()).unwrap();
    std::fs::write(&e.bin, b"binary v2").unwrap();
    let sys = Fake::new();
    *sys.user.borrow_mut() = true;
    let out = install(&sys, &e.opts()).unwrap();
    assert!(out.binary_updated && !out.config_written && !out.cert_created);
    assert_eq!(
        std::fs::read(e.f("/usr/local/bin/afas-entra-sync")).unwrap(),
        b"binary v2"
    );
}

#[test]
fn reconfigure_renew_and_replace_keep_backups() {
    let e = Env::new();
    install(&Fake::new(), &e.opts()).unwrap();
    let old_cert = std::fs::read(e.f("/etc/afas-entra-sync/cert.pem")).unwrap();
    let sys = Fake::new();
    *sys.user.borrow_mut() = true;
    let mut o = e.opts();
    o.reconfigure = true;
    o.renew_cert = true;
    o.replace_token = true;
    o.answers.employee_count = Some(1000);
    o.answers.token = Some("NEWTOKEN123".into());
    let out = install(&sys, &o).unwrap();
    assert!(out.config_written && out.cert_created && out.token_written);
    let dir = e.f("/etc/afas-entra-sync");
    let backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|d| d.ok())
        .map(|d| d.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("config.toml.bak-"))
        .collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(std::fs::read(dir.join("cert.pem.old")).unwrap(), old_cert);
    assert_eq!(mode(&dir.join("key.pem.old")), 0o600);
    assert_eq!(
        std::fs::read_to_string(dir.join("afas.token")).unwrap(),
        "NEWTOKEN123"
    );
    let c = Config::parse(&std::fs::read_to_string(dir.join("config.toml")).unwrap()).unwrap();
    assert_eq!(c.policy.min_records, 900);
}

#[test]
fn enable_sync_and_gui() {
    let e = Env::new();
    let sys = Fake::new();
    let mut o = e.opts();
    o.enable_sync = true;
    o.gui = true;
    let out = install(&sys, &o).unwrap();
    assert!(out.sync_enabled);
    let ran = sys.ran();
    assert!(
        ran.contains(
            &"systemctl enable --now afas-entra-sync.timer afas-entra-sync-check-logs.timer"
                .to_string()
        )
    );
    assert!(ran.contains(&"systemctl restart afas-entra-sync-gui.service".to_string()));
    let gui =
        std::fs::read_to_string(e.f("/etc/systemd/system/afas-entra-sync-gui.service")).unwrap();
    assert!(gui.contains("serve --listen 127.0.0.1:8080"));
    let c =
        Config::parse(&std::fs::read_to_string(e.f("/etc/afas-entra-sync/config.toml")).unwrap())
            .unwrap();
    assert!(c.gui.enabled);
}

#[test]
fn interactive_prompts_retry_until_valid() {
    let e = Env::new();
    let sys = Fake::new();
    let mut o = e.opts();
    o.answers = Answers::default();
    let mut sys = sys;
    sys.tty = true;
    *sys.inputs.borrow_mut() = [
        "bad token!",       // token: refused
        "ABCDEF0123456789", // token
        "rest.example",     // env: refused
        "12345",            // env
        "",                 // connector: default
        "not-a-guid",       // tenant: refused
        TENANT,
        CLIENT,
        SP,
        JOB,
        "example.com, example.org",
        "zero", // count: refused
        "250",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    install(&sys, &o).unwrap();
    let c =
        Config::parse(&std::fs::read_to_string(e.f("/etc/afas-entra-sync/config.toml")).unwrap())
            .unwrap();
    assert_eq!(c.afas.connector, "Entra_Medewerkers");
    assert_eq!(
        c.policy.allowed_upn_domains,
        vec!["example.com", "example.org"]
    );
    assert_eq!(c.policy.min_records, 225);
    assert!(sys.inputs.borrow().is_empty());
}

#[test]
fn unattended_without_answers_fails_before_writing_config() {
    let e = Env::new();
    let sys = Fake::new();
    let mut o = e.opts();
    o.answers.tenant_id = None;
    let err = install(&sys, &o).unwrap_err();
    assert!(err.contains("tenant"), "{err}");
    assert!(
        !e.root().exists(),
        "nothing written when an answer is missing"
    );
    // Invalid flag value is refused, not written.
    let mut o = e.opts();
    o.answers.client_id = Some("nope".into());
    assert!(install(&sys, &o).unwrap_err().contains("GUID"));
    let mut o = e.opts();
    o.answers.token = Some("bad token".into());
    assert!(install(&Fake::new(), &o).is_err());
}

#[test]
fn not_root_is_refused() {
    let e = Env::new();
    let mut sys = Fake::new();
    sys.root = false;
    assert!(install(&sys, &e.opts()).unwrap_err().contains("root"));
    assert!(!e.root().exists());
}

#[test]
fn without_systemd_no_units() {
    let e = Env::new();
    let mut sys = Fake::new();
    sys.systemd = false;
    let out = install(&sys, &e.opts()).unwrap();
    assert!(!out.units_written);
    assert!(!e.f("/etc/systemd/system").exists());
    assert!(sys.ran().iter().all(|r| !r.starts_with("systemctl")));
}

#[test]
fn uninstall_keeps_data_unless_purged() {
    let e = Env::new();
    install(&Fake::new(), &e.opts()).unwrap();
    let sys = Fake::new();
    *sys.user.borrow_mut() = true;
    uninstall(
        &sys,
        &UninstallOptions {
            root: e.root(),
            purge: false,
            yes: false,
        },
    )
    .unwrap();
    assert!(!e.f("/usr/local/bin/afas-entra-sync").exists());
    assert!(!e.f("/etc/systemd/system/afas-entra-sync.timer").exists());
    assert!(e.f("/etc/afas-entra-sync/key.pem").exists());
    assert!(!sys.ran().iter().any(|r| r.starts_with("userdel")));
    // Purge without --yes and without a terminal: refused, nothing deleted.
    assert!(
        uninstall(
            &sys,
            &UninstallOptions {
                root: e.root(),
                purge: true,
                yes: false
            }
        )
        .is_err()
    );
    assert!(e.f("/etc/afas-entra-sync").exists());
    uninstall(
        &sys,
        &UninstallOptions {
            root: e.root(),
            purge: true,
            yes: true,
        },
    )
    .unwrap();
    assert!(!e.f("/etc/afas-entra-sync").exists());
    assert!(!e.f("/var/lib/afas-entra-sync").exists());
    assert!(sys.ran().contains(&"userdel afas-sync".to_string()));
}

#[test]
fn generated_certificate_is_usable_for_entra() {
    let (cert, key) = new_certificate().unwrap();
    // Same check the program does at runtime: one certificate + a valid RSA key.
    afas_entra_sync::entra::Credential::certificate(cert.as_bytes(), key.into_bytes()).unwrap();
    assert_eq!(thumbprint(cert.as_bytes()).unwrap().len(), 40);
}

#[test]
fn config_builder_accepts_full_url_and_keeps_comments() {
    let mut a = answers();
    a.afas_env = Some("https://99999.resttest.afas.online/ProfitRestServices/".into());
    a.connector = Some("My_Connector".into());
    let text = build_config(&a, false).unwrap();
    assert!(text.contains("# Extra attributes, each with an on/off toggle"));
    let c = Config::parse(&text).unwrap();
    assert_eq!(
        c.afas.base_url,
        "https://99999.resttest.afas.online/ProfitRestServices"
    );
    assert_eq!(c.afas.connector, "My_Connector");
}

#[test]
fn unit_files_are_hardened_and_run_as_service_user() {
    for (name, body) in unit_files(true) {
        if name.ends_with(".service") {
            assert!(body.contains("User=afas-sync"), "{name}");
            assert!(body.contains("ProtectSystem=strict"), "{name}");
            assert!(body.contains("NoNewPrivileges=true"), "{name}");
            assert!(body.contains("CapabilityBoundingSet=\n"), "{name}");
        } else {
            assert!(body.contains("Persistent=true"), "{name}");
        }
    }
    let sync = &unit_files(false)[0].1;
    assert!(sync.contains("sync --apply"));
    assert_eq!(unit_files(false).len(), 4);
}

// ------------------------------------------------------------------ module-setup

fn setup(e: &Env, sys: &Fake, m: SetupModule, renew: bool) -> Result<String, String> {
    module_setup(
        sys,
        &ModuleSetupOptions {
            root: e.root(),
            module: m,
            renew,
        },
    )
}

#[test]
fn module_setup_needs_root_and_an_installation() {
    let e = Env::new();
    let mut sys = Fake::new();
    assert!(
        setup(&e, &sys, SetupModule::Roles, false)
            .unwrap_err()
            .contains("install")
    );
    sys.root = false;
    assert!(
        setup(&e, &sys, SetupModule::Roles, false)
            .unwrap_err()
            .contains("root")
    );
    assert!(SetupModule::parse("payroll").is_err());
    assert_eq!(SetupModule::parse("joiner").unwrap(), SetupModule::Joiner);
}

#[test]
fn module_setup_creates_a_private_key_and_prints_a_working_config_section() {
    let e = Env::new();
    let sys = Fake::new();
    install(&sys, &e.opts()).unwrap();
    sys.said.borrow_mut().clear();
    sys.chowned.borrow_mut().clear();
    let tp = setup(&e, &sys, SetupModule::Roles, false).unwrap();
    let key = e.f("/etc/afas-entra-sync/roles-key.pem");
    let cert = e.f("/etc/afas-entra-sync/roles-cert.pem");
    assert_eq!(mode(&key), 0o600);
    assert_eq!(mode(&cert), 0o644);
    assert!(
        sys.chowned
            .borrow()
            .iter()
            .any(|(p, uid)| p == &key && *uid == 990)
    );
    assert_eq!(tp, thumbprint(&std::fs::read(&cert).unwrap()).unwrap());
    let said = sys.said.borrow().join("\n");
    assert!(
        said.contains("GroupMember.ReadWrite.All, User.Read.All"),
        "{said}"
    );
    assert!(said.contains(&tp));
    assert!(said.contains("afas-entra-sync doctor"));

    // The printed section, with the placeholders filled in, is a valid config.
    let start = said.find("[roles]").unwrap();
    let end = said[start..].find("  5.").map_or(said.len(), |i| start + i);
    let section = said[start..end]
        .replace("<application id>", "c0000000-0000-0000-0000-000000000001")
        .replace(
            "<object id of a cloud security group>",
            "a1a1a1a1-0000-0000-0000-000000000001",
        )
        .replace(
            "/etc/afas-entra-sync/",
            &format!("{}/", e.f("/etc/afas-entra-sync").display()),
        );
    let cfg_path = e.f("/etc/afas-entra-sync/config.toml");
    let text = std::fs::read_to_string(&cfg_path).unwrap() + "\n" + &section;
    let cfg = Config::parse(&text).unwrap_or_else(|err| panic!("{err}\n{section}"));
    assert!(cfg.roles.unwrap().enabled);

    // Again: kept. With --renew: new certificate, old one kept, upload hint only.
    assert_eq!(setup(&e, &sys, SetupModule::Roles, false).unwrap(), tp);
    sys.said.borrow_mut().clear();
    let tp2 = setup(&e, &sys, SetupModule::Roles, true).unwrap();
    assert_ne!(tp, tp2);
    assert!(e.f("/etc/afas-entra-sync/roles-key.pem.old").exists());
    assert_eq!(mode(&key), 0o600);
    let said = sys.said.borrow().join("\n");
    assert!(
        said.contains("Upload the new") && !said.contains("[roles]"),
        "{said}"
    );
}

#[test]
fn module_setup_tells_joiner_not_to_grant_mail_send_in_entra() {
    let e = Env::new();
    let sys = Fake::new();
    install(&sys, &e.opts()).unwrap();
    for (m, perm) in [
        (SetupModule::Joiner, "UserAuthMethod-TAP.ReadWrite.All"),
        (SetupModule::Leaver, "User.RevokeSessions.All"),
    ] {
        sys.said.borrow_mut().clear();
        setup(&e, &sys, m, false).unwrap();
        let said = sys.said.borrow().join("\n");
        assert!(said.contains(perm), "{said}");
        assert_eq!(
            said.contains("do NOT grant it in Entra"),
            m == SetupModule::Joiner
        );
        assert!(
            e.f(&format!("/etc/afas-entra-sync/{}-key.pem", m.key()))
                .exists()
        );
    }
}
