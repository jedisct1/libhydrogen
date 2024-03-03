project(
  'libhydrogen',
  'c',
  license: 'ISC',
  default_options: [
    'buildtype=minsize',
    'default_library=static',
    'warning_level=2',
  ],
)

cc = meson.get_compiler('c')

cflags = cc.get_supported_arguments(
  '-Wbad-function-cast',
  '-Wcast-align',
  '-Wcast-qual',
  '-Wdiv-by-zero',
  '-Wfloat-equal',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wno-type-limits',
  '-Wno-unknown-pragmas',
  '-Wpointer-arith',
  '-Wredundant-decls',
  '-Wstrict-prototypes',
  '-Wswitch-enum',
  '-fno-exceptions',
  '-mtune=native',
)
add_project_arguments(cflags, language: 'c')

include_dirs = include_directories('.')

sources = files(
  'hydrogen.c',
)

libhydrogen = library(
  'hydrogen',
  sources,
  include_directories: include_dirs,
  install: true,
)

tests = executable(
  'tests',
  files('tests/tests.c'),
  link_with: libhydrogen,
)
test('tests', tests)

install_headers(files('hydrogen.h'))

pkgconfig = import('pkgconfig')
pkgconfig.generate(
  libhydrogen,
  name: 'libhydrogen',
  description: 'Lightweight, secure, easy-to-use crypto library suitable for constrained environments.',
  url: 'https://libhydrogen.org/',
)

libhydrogen_dep = declare_dependency(
  include_directories: include_dirs,
  link_with: libhydrogen,
)
