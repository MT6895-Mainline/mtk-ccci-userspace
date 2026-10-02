import test_rpc_sar
import test_source_safety
import test_launcher
import test_fs_contract


def main():
    test_source_safety.test_no_credentials_or_device_identity()
    test_source_safety.test_private_paths_are_configurable()
    test_rpc_sar.test_sar_reply_uses_stock_no_match_sentinel()
    test_rpc_sar.test_rpc_property_and_unknown()
    test_rpc_sar.test_rpc_invalid_frames()
    test_launcher.test_cli_help_is_offline()
    test_launcher.test_writable_mount_is_rejected()
    test_launcher.test_wrong_mount_is_rejected()
    test_launcher.test_write_root_cannot_overlap_backing()
    test_fs_contract.test_frames_and_path_guards()
    test_fs_contract.test_cmpt_writes_only_overlay()
    test_fs_contract.test_private_drive_and_missing_ota()
    print("PASS: 12 userspace source, RPC, FS, and launcher checks")


if __name__ == "__main__":
    main()
