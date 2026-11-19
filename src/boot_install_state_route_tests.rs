// Included into `netboot::tests`: what a network boot starts by itself,
// against a Nest with a verified, active runtime. The rule: the list of
// computers Tiaris sends decides. A computer that is not installed gets the
// installer every time it starts from the network; an installed one starts
// from its disk.
mod boot_install_state_routes {
    use super::*;
    use crate::{
        boot_identity::uuid_fingerprint,
        models::{BootProfileType, CreateBootProfileRequest, CreateDeviceRequest},
    };
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    const MAC: &str = "aa:bb:cc:dd:ee:ff";
    const UUID_A: &str = "4c4c4544-0042-3510-8051-b4c04f4e3732";
    const UUID_B: &str = "6a1e2f3c-9b8d-4e7f-a1b2-c3d4e5f60718";
    const INSTALLER: &str = "loading signed workstation installer runtime";
    const DISK_FIRST: &str = ":known_local_efi\nsanboot --no-describe --drive 0x80";

    async fn nest() -> (RuntimeFilesystemFixture, Router) {
        let fixture = RuntimeFilesystemFixture::new().await;
        let descriptor = fixture.install_bundle("1.0.161", &"e".repeat(64)).await;
        fixture.activate(&descriptor, None).await;
        profile(&fixture.state, "Enroll", true, false).await;
        let app = crate::routes::router(fixture.state.clone());
        (fixture, app)
    }

    async fn profile(state: &AppState, name: &str, is_default: bool, one_time: bool) -> i64 {
        let profile = crate::db::create_profile(
            &state.db,
            CreateBootProfileRequest {
                name: name.to_string(),
                description: None,
                profile_type: BootProfileType::NestInstaller,
                enabled: Some(true),
                is_default: Some(is_default),
                one_time: Some(one_time),
                raw_script: None,
            },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE boot_profiles SET managed_profile_id = ? WHERE id = ?")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(profile.id)
            .execute(&state.db)
            .await
            .unwrap();
        profile.id
    }

    /// The Nest saw this MAC address before.
    async fn seen_before(state: &AppState, one_time_profile_id: Option<i64>) -> i64 {
        crate::db::create_device(
            &state.db,
            CreateDeviceRequest {
                mac: MAC.to_string(),
                hostname: None,
                serial_number: None,
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id,
            },
        )
        .await
        .unwrap()
        .id
    }

    /// What Tiaris last said: the computers it knows, and whether that is
    /// all of them.
    async fn tiaris_lists(state: &AppState, machines: &[(&str, bool)], complete: bool) {
        let record = crate::boot_machines::Record {
            machines: machines
                .iter()
                .map(|(uuid, installed)| (uuid_fingerprint(uuid), *installed))
                .collect(),
            machines_complete: complete,
            ..Default::default()
        };
        crate::boot_machines::save(&state.config.paths.data_dir, &record)
            .await
            .unwrap();
    }

    async fn boot(app: &Router, uri: &str) -> String {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    fn starts_installer(script: &str) -> bool {
        script.contains(INSTALLER) && !script.contains("sanboot")
    }

    fn starts_disk(script: &str) -> bool {
        script.contains(DISK_FIRST) && !script.contains(INSTALLER)
    }

    #[tokio::test]
    async fn a_new_computer_gets_the_installer_every_time_until_it_is_installed() {
        let (fixture, app) = nest().await;
        let uri = format!("/boot/{MAC}?uuid={UUID_A}");
        tiaris_lists(&fixture.state, &[(UUID_B, true)], true).await;

        // Tiaris does not know it: the installer, the first time and after
        // every restart, although the Nest has seen its MAC by then.
        for _ in 0..3 {
            assert!(starts_installer(&boot(&app, &uri).await));
        }
        // Waiting for approval on Add, installing, or failed halfway: Tiaris
        // lists it as not installed.
        tiaris_lists(&fixture.state, &[(UUID_A, false), (UUID_B, true)], true).await;
        for _ in 0..2 {
            assert!(starts_installer(&boot(&app, &uri).await));
        }
        // Installed: its disk from now on.
        tiaris_lists(&fixture.state, &[(UUID_A, true), (UUID_B, true)], true).await;
        for _ in 0..2 {
            assert!(starts_disk(&boot(&app, &uri).await));
        }
        let events = crate::db::list_boot_events(&fixture.state.db, 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 7);
        assert!(events[0].selected_profile_id.is_none());
        assert_eq!(events[2].selected_profile_name.as_deref(), Some("Enroll"));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn an_installed_computer_starts_from_its_disk_on_a_nest_that_never_saw_it() {
        let (fixture, app) = nest().await;
        tiaris_lists(&fixture.state, &[(UUID_A, true)], true).await;
        // A new or replaced Nest: the MAC is new to it, the computer is not.
        assert!(starts_disk(&boot(&app, &format!("/boot/{MAC}?uuid={UUID_A}")).await));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn a_computer_whose_install_failed_halfway_gets_the_installer_again() {
        let (fixture, app) = nest().await;
        seen_before(&fixture.state, None).await;
        tiaris_lists(&fixture.state, &[(UUID_A, false)], true).await;
        // Under the old rule this MAC was known and got its (unfinished) disk.
        assert!(starts_installer(
            &boot(&app, &format!("/boot/{MAC}?uuid={UUID_A}")).await
        ));
        // A list that was cut still names it.
        tiaris_lists(&fixture.state, &[(UUID_A, false)], false).await;
        assert!(starts_installer(
            &boot(&app, &format!("/boot/{MAC}?uuid={UUID_A}")).await
        ));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn a_computer_the_administrator_removed_gets_the_installer() {
        let (fixture, app) = nest().await;
        seen_before(&fixture.state, None).await;
        let uri = format!("/boot/{MAC}?uuid={UUID_A}");
        tiaris_lists(&fixture.state, &[(UUID_A, true), (UUID_B, true)], true).await;
        assert!(starts_disk(&boot(&app, &uri).await));

        // Removed in Tiaris: the complete list no longer names it. Its disk
        // is untouched; the installer waits on Add for approval.
        tiaris_lists(&fixture.state, &[(UUID_B, true)], true).await;
        assert!(starts_installer(&boot(&app, &uri).await));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn a_reinstall_tiaris_asked_for_starts_on_an_installed_computer_once() {
        let (fixture, app) = nest().await;
        let reinstall = profile(&fixture.state, "Reinstall", false, true).await;
        let row = seen_before(&fixture.state, Some(reinstall)).await;
        let uri = format!("/boot/{MAC}?uuid={UUID_A}");
        tiaris_lists(&fixture.state, &[(UUID_A, true)], true).await;

        assert!(starts_installer(&boot(&app, &uri).await));
        let device = crate::db::get_device(&fixture.state.db, row).await.unwrap();
        assert_eq!(device.one_time_profile_id, None, "consumed");
        assert_eq!(device.last_selected_profile_id, Some(reinstall));

        // After that the list decides again: its disk while Tiaris still
        // lists it as installed, the installer once it is being installed.
        assert!(starts_disk(&boot(&app, &uri).await));
        tiaris_lists(&fixture.state, &[(UUID_A, false)], true).await;
        assert!(starts_installer(&boot(&app, &uri).await));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn without_a_list_from_tiaris_only_a_mac_never_seen_gets_the_installer() {
        let (fixture, app) = nest().await;
        let uri = format!("/boot/{MAC}?uuid={UUID_A}");

        // No list at all: the first time the installer, later the disk.
        assert!(starts_installer(&boot(&app, &uri).await));
        assert!(starts_disk(&boot(&app, &uri).await));

        // A cut list that does not name the computer says nothing about it.
        tiaris_lists(&fixture.state, &[(UUID_B, false)], false).await;
        assert!(starts_disk(&boot(&app, &uri).await));
        assert!(starts_installer(
            &boot(&app, &format!("/boot/aa-bb-cc-dd-ee-01?uuid={UUID_A}")).await
        ));

        // Nor does a complete list about a computer without a usable system
        // UUID.
        tiaris_lists(&fixture.state, &[(UUID_B, false)], true).await;
        for uuid in ["", "00000000-0000-0000-0000-000000000000"] {
            assert!(starts_disk(&boot(&app, &format!("/boot/{MAC}?uuid={uuid}")).await));
        }
        assert!(starts_installer(&boot(&app, "/boot/aa-bb-cc-dd-ee-02").await));
        assert!(starts_disk(&boot(&app, "/boot/aa-bb-cc-dd-ee-02").await));
        fixture.cleanup();
    }

    #[tokio::test]
    async fn a_computer_that_is_not_installed_gets_the_menu_when_no_installer_is_default() {
        let fixture = RuntimeFilesystemFixture::new().await;
        let descriptor = fixture.install_bundle("1.0.161", &"e".repeat(64)).await;
        fixture.activate(&descriptor, None).await;
        profile(&fixture.state, "Enroll", false, false).await;
        seen_before(&fixture.state, None).await;
        tiaris_lists(&fixture.state, &[(UUID_A, false)], true).await;
        let app = crate::routes::router(fixture.state.clone());

        // The menu at once, without trying a disk that has no system.
        let menu = boot(&app, &format!("/boot/{MAC}?uuid={UUID_A}")).await;
        assert!(menu.contains("item profile_"));
        assert!(!menu.contains("known_local"));
        fixture.cleanup();
    }
}
