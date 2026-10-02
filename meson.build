project('mtk-ccci-userspace', version: '0.1.0')

install_data(
  'src/mtk_ccci_userspace/mdinit.py',
  'src/mtk_ccci_userspace/qqc_rpc_sar.py',
  'src/mtk_ccci_userspace/start_owner.py',
  install_dir: get_option('libexecdir') / 'mtk-ccci',
)

python = import('python').find_installation('python3')
test('offline-protocols', python,
  args: [meson.current_source_dir() / 'tests/test_runner.py'],
)

install_data(
  'systemd/mtk-ccci-owner.service.example',
  install_dir: get_option('datadir') / 'mtk-ccci',
)

install_data(
  'config/mtk-ccci.env.example',
  install_dir: get_option('datadir') / 'mtk-ccci',
)
