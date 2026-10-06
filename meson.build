project('mtk-ccci-userspace', version: '0.1.0')

python = import('python').find_installation('python3')

ccci_libexec = get_option('libexecdir') / 'mtk-ccci'
ccci_share = get_option('datadir') / 'mtk-ccci'

install_data(
  'src/mtk_ccci_userspace/mdinit.py',
  'src/mtk_ccci_userspace/qqc_rpc_sar.py',
  'src/mtk_ccci_userspace/start_owner.py',
  # pearl (MT6895 Xiaomi) bring-up helpers
  'src/mtk_ccci_userspace/at_cfun.py',
  'src/mtk_ccci_userspace/data_up.py',
  'src/mtk_ccci_userspace/mm_tune.py',
  install_dir: ccci_libexec,
)

install_data(
  'systemd/mtk-ccci-owner.service.example',
  'systemd/mtk-ccci-at-cfun.service.example',
  'systemd/mtk-ccci-data.service.example',
  'systemd/mtk-ccci-mm-tune.service.example',
  'systemd/ModemManager.service.d-10-pearl-ccci.conf.example',
  'config/mtk-ccci.env.example',
  'config/mtk-ccci-data.conf.example',
  'udev/98-mtk-ccci-net.rules',
  'udev/99-mtk-ccci-at.rules',
  'docs/PEARL.md',
  'docs/MODEMANAGER.md',
  install_dir: ccci_share,
)

test('offline-protocols', python,
  args: [meson.current_source_dir() / 'tests/test_runner.py'],
)

install_data(
  'tools/mipc-test.py',
  install_dir: ccci_share / 'tools',
)
