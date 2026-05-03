; NSIS installer hooks for Ember

!macro NSIS_HOOK_POSTINSTALL
  ; Force Windows Shell to flush the icon cache so the exe's embedded
  ; icon is picked up immediately by any shortcuts.
  ; SHCNE_ASSOCCHANGED (0x08000000) | SHCNF_IDLIST|SHCNF_FLUSH (0x1000)
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0x1000, p 0, p 0)'

  ; Recreate the desktop shortcut (if it exists) with an explicit icon
  ; reference. Prefer the packaged .ico file to avoid Windows using a
  ; stale or differently-rendered embedded exe icon.
  IfFileExists "$DESKTOP\${PRODUCTNAME}.lnk" 0 _skip_icon_fix
    Delete "$DESKTOP\${PRODUCTNAME}.lnk"
    IfFileExists "$INSTDIR\resources\icon.ico" 0 _shortcut_with_exe_icon
      CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "" "$INSTDIR\resources\icon.ico" 0
      Goto _skip_icon_fix
    _shortcut_with_exe_icon:
      CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "" "$INSTDIR\${MAINBINARYNAME}.exe" 0
  _skip_icon_fix:
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Tauri's default uninstaller only deletes "$APPDATA\${BUNDLEID}" and
  ; "$LOCALAPPDATA\${BUNDLEID}" when the user ticks "Remove application
  ; data". Ember does NOT store anything under the bundle-id path; all
  ; on-disk state (database, config, identity, logs, sharing index)
  ; lives under directories::ProjectDirs("com", "ember", "p2p"), which
  ; on Windows resolves to:
  ;   %APPDATA%\ember\p2p\         (data + config + log files)
  ;   %LOCALAPPDATA%\ember\p2p\    (cache, if ever used)
  ; The default removal therefore leaves every user-visible bit of
  ; state behind in Roaming after an uninstall — exactly the bug the
  ; user reported. Recursively delete those trees here when (and only
  ; when) the checkbox is set.
  ;
  ; We intentionally guard on $DeleteAppDataCheckboxState so a user who
  ; UNticks the box keeps their friends/database/config across a
  ; reinstall, matching the behaviour the checkbox label promises.
  ; The NSIS_HOOK_POSTUNINSTALL macro fires inside SetShellVarContext
  ; current (set by the surrounding Tauri uninstaller block), so
  ; $APPDATA / $LOCALAPPDATA resolve to the per-user Roaming /
  ; Local AppData directories.
  ${If} $DeleteAppDataCheckboxState == 1
    SetShellVarContext current
    RmDir /r "$APPDATA\ember\p2p"
    RmDir /r "$LOCALAPPDATA\ember\p2p"
    ; Best-effort: if the parent "ember" directory is now empty (no
    ; sibling Tauri-family apps), drop it too. RmDir without /r only
    ; removes empty directories, so this is safe.
    RmDir "$APPDATA\ember"
    RmDir "$LOCALAPPDATA\ember"
  ${EndIf}
!macroend
