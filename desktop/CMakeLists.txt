cmake_minimum_required(VERSION 3.21)

project(anubis-desktop
  VERSION 2.1.0
  DESCRIPTION "Post-quantum file encryption vault"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2 Network Svg)

qt_standard_project_setup(REQUIRES 6.5)

qt_add_executable(anubis-desktop
  src/main.cpp
  src/app.cpp
  src/app.hpp
  src/datastream.cpp
  src/datastream.hpp
  src/fileview.cpp
  src/fileview.hpp
  src/openrequest.cpp
  src/openrequest.hpp
  src/process.cpp
  src/process.hpp
)

target_compile_definitions(anubis-desktop
  PRIVATE ANUBIS_DESKTOP_VERSION="${PROJECT_VERSION}")

# The generated QML type registrations include the headers by bare name.
target_include_directories(anubis-desktop PRIVATE src)

# The QML lives in qml/ on disk but at the module root in the resource tree,
# so `import "Model.js"` and the singleton lookups resolve the same way they
# would in a flat directory.
foreach(qml_file Main.qml Vault.qml Service.qml Color.qml Style.qml Model.js)
  set_source_files_properties(qml/${qml_file}
    PROPERTIES QT_RESOURCE_ALIAS ${qml_file})
endforeach()

# Model.js is imported by relative path from the QML that needs it, not as a
# module type, so it gets no qmldir entry. Its `.pragma library` already makes
# it one shared instance rather than one per importing document.
set_source_files_properties(qml/Model.js
  PROPERTIES QT_QML_SKIP_QMLDIR_ENTRY TRUE)

# Color and Style are singletons: one palette and one metric scale for the
# whole surface, not a copy per consumer.
set_source_files_properties(qml/Color.qml qml/Style.qml
  PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

qt_add_qml_module(anubis-desktop
  URI Anubis
  VERSION 1.0
  QML_FILES
    qml/Main.qml
    qml/Vault.qml
    qml/Service.qml
    qml/Color.qml
    qml/Style.qml
    qml/Model.js
)

qt_add_resources(anubis-desktop "appicon"
  PREFIX "/icons"
  BASE packaging
  FILES packaging/anubis-vault.svg)

target_link_libraries(anubis-desktop PRIVATE
  Qt6::Core
  Qt6::Gui
  Qt6::Qml
  Qt6::Quick
  Qt6::QuickControls2
  Qt6::Network
  Qt6::Svg
)

include(CTest)
if(BUILD_TESTING)
  find_package(Qt6 6.5 REQUIRED COMPONENTS QuickTest Test)
  qt_add_executable(anubis-desktop-process-test
    tests/process_lifecycle_test.cpp
    src/datastream.cpp
    src/datastream.hpp
    src/fileview.cpp
    src/fileview.hpp
    src/openrequest.cpp
    src/openrequest.hpp
    src/process.cpp
    src/process.hpp
  )
  target_include_directories(anubis-desktop-process-test PRIVATE src)
  target_link_libraries(anubis-desktop-process-test PRIVATE
    Qt6::Core
    Qt6::Qml
    Qt6::Test
  )
  add_test(NAME process-lifecycle COMMAND anubis-desktop-process-test)
  add_test(NAME qml-model
    COMMAND Qt6::qmltestrunner
      -input ${CMAKE_CURRENT_SOURCE_DIR}/tests/qml)
  set_tests_properties(qml-model PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()

include(GNUInstallDirs)

install(TARGETS anubis-desktop
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES packaging/dev.anubis.Vault.desktop
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/applications)

install(FILES packaging/anubis-vault.svg
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps
  RENAME dev.anubis.Vault.svg)

install(FILES packaging/dev.anubis.Vault.metainfo.xml
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/metainfo)

install(FILES packaging/anubis-container.xml packaging/anubis-source.xml
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/mime/packages)

# Right-click encrypt/decrypt in Nautilus. Installed under the user's data dir
# because nautilus-python only scans ~/.local/share and /usr/share.
install(FILES packaging/anubis-nautilus.py
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/nautilus-python/extensions
  RENAME anubis.py)

# A sealed file gets its own mark rather than wearing the launcher's icon.
install(FILES packaging/anubis-container-mime.svg
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/mimetypes
  RENAME application-vnd.anubis.container.svg)
