; Ganchos do instalador do Windows (NSIS). Usados só no build de release (tauri.release.conf.json).
;
; O instalador instala a interface e o CLI. O CLI fica em "<pasta de instalação>\cli\oblivion.exe" e essa pasta
; entra no PATH do USUÁRIO (não do sistema), para o comando `oblivion` funcionar em terminais novos. A
; desinstalação tira só essa pasta do PATH. Nada é feito com privilégios de administrador, e nada é baixado.
;
; O PATH é gravado direto no registro, SEM expandir e mantendo o tipo "expansível" (REG_EXPAND_SZ): quem usa
; `[Environment]::SetEnvironmentVariable` perde entradas como %USERPROFILE%\... que muita gente tem no PATH.
; No fim, apagar uma variável que não existe faz o Windows avisar os programas abertos de que o ambiente mudou.

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$$d = '$INSTDIR\cli'; $$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $$true); $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); $$parts = @($$p -split ';' | Where-Object { $$_ }); if ($$parts -notcontains $$d) { $$k.SetValue('Path', (($$parts + $$d) -join ';'), 'ExpandString') }; $$k.Close(); [Environment]::SetEnvironmentVariable('OBLIVION_NOTIFY', $$null, 'User')"`
  Pop $0
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  nsExec::ExecToLog `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$$d = '$INSTDIR\cli'; $$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $$true); $$p = [string]$$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames'); if ($$p) { $$parts = @($$p -split ';' | Where-Object { $$_ -and ($$_ -ne $$d) }); $$k.SetValue('Path', ($$parts -join ';'), 'ExpandString') }; $$k.Close(); [Environment]::SetEnvironmentVariable('OBLIVION_NOTIFY', $$null, 'User')"`
  Pop $0
!macroend
