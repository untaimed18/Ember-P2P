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
