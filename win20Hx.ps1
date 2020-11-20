# Разрешить запускать скрипты только в текущем сеансе PowerShell;
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Выводим запрос на запуск скрипта от имени Админимтратора;
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# Инициализация меню;
function Show-Menu
{
	param (
		[string]$Title = 'Скрипт настройки Windows 10 Build 2004 и 2009 ( 20H1 | 20H2 )'
	)
	cls
	Write-Host "================ $Title ================"
	Write-Host "---"
	Write-Host "1: Отключить службы;"
	Write-Host "2: Отключить задачи диагностического отслеживания;"
	Write-Host "3: Отключить компоненты Windows;"
	Write-Host "4: Отключить обновления Windows;"
	Write-Host "5: Удалить встроенные приложения из магазина Windows Store;"
	Write-Host "6: Примеить Tweak's;"
	Write-Host "7: Настроить систему для работы с SSD;"
	Write-Host "8: Удалить OneDrive;"
	Write-Host "9: Выполнить очистку папки WinSxS;"
	Write-Host "10: Установить приложения с помощью WinGet (App Installer);"
	Write-Host "---"
	Write-Host "Q: Нажмите 'Q' чтобы выйти."
}

# Запуск наборов функций;
#
# Отключение служб;
Function f_disable_services {
	$services = @(
		# Функциональные возможности для подключенных пользователей и телеметрия
		"DiagTrack"
		# Служба маршрутизации push-сообщений на основе протокола WAP
		"dmwappushservice"
		# Стандартная служба сборщика центра диагностики Microsoft
		"diagnosticshub.standardcollector.service"
		# Служба антивирусной программы Microsoft Defender
		"WinDefend"
		# Служба оркестратора обновлений
		"UsoSvc"
		# Служба сенсорной клавиатуры и панели рукописного ввода
		"TabletInputService"
		# Служба управления радио
		"RmSvc"
	)
	ForEach ($service in $services) {
		echo "Остановка службы: $service"
		Get-Service -Name $service | Stop-Service -Force
		echo "Отключение службы: $service"
		Get-Service -Name $service | Set-Service -StartupType Disabled
	}
}

# Отключить задачи диагностического отслеживания;
function f_disable_scheduledtasks {
	$ScheduledTaskList = @(
		# Собирает телеметрические данные программы при участии в Программе улучшения качества программного обеспечения Майкрософт
		"Microsoft Compatibility Appraiser",
		# Сбор телеметрических данных программы при участии в программе улучшения качества ПО
		"ProgramDataUpdater",
		# Эта задача собирает и загружает данные SQM при участии в программе улучшения качества программного обеспечения
		"Proxy",
		# Если пользователь изъявил желание участвовать в программе по улучшению качества программного обеспечения Windows, эта задача будет собирать и отправлять сведения о работе программного обеспечения в Майкрософт
		"Consolidator",
		# При выполнении задачи программы улучшения качества ПО шины USB (USB CEIP) осуществляется сбор статистических данных об использовании универсальной последовательной шины USB и с ведений о компьютере, которые направляются инженерной группе Майкрософт по вопросам подключения устройств в Windows
		"UsbCeip",
		# Для пользователей, участвующих в программе контроля качества программного обеспечения, служба диагностики дисков Windows предоставляет общие сведения о дисках и системе в корпорацию Майкрософт
		"Microsoft-Windows-DiskDiagnosticDataCollector",
		# Защищает файлы пользователя от случайной потери за счет их копирования в резервное расположение, когда система находится в автоматическом режиме
		"File History (maintenance mode)",
		# Измеряет быстродействие и возможности системы
		"WinSAT",
		# Эта задача показывает различные тосты (всплывающие уведомления) приложения "Карты"
		"MapsToastTask",
		# Эта задача проверяет наличие обновлений для карт, загруженных для автономного использования
		"MapsUpdateTask",
		# Инициализация контроля и применения правил семейной безопасности
		"FamilySafetyMonitor",
		# Синхронизирует последние параметры со службой функций семьи учетных записей Майкрософт
		"FamilySafetyRefreshTask",
		# XblGameSave Standby Task
		"XblGameSaveTask"
	)
	# Если устройство не является ноутбуком, отключить также и FODCleanupTask
	if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2) {
		# Windows Hello
		$ScheduledTaskList += "FODCleanupTask"
	}
	Get-ScheduledTask -TaskName $ScheduledTaskList | Disable-ScheduledTask
}

# Отключить компоненты Windows;
Function f_disable_components {
	$WindowsOptionalFeatures = @(
		# Компоненты прежних версий
		"LegacyComponents"
		# Компоненты работы с мультимедиа
		"MediaPlayback"
		# Средство записи XPS-документов (Microsoft)
		"Printing-XPSServices-Features"
		# Клиент рабочих папок
		"WorkFolders-Client"
	)
	Disable-WindowsOptionalFeature -Online -FeatureName $WindowsOptionalFeatures -NoRestart
}

# Отключить обновления Windows;
Function f_disable_winupdate {
	$services = @(
		# Служба оркестратора обновлений
		"UsoSvc"
		# Центр обновления Windows
		"wuauserv"
	)
	ForEach ($service in $services) {
		echo "Остановка службы: $service"
		Get-Service -Name $service | Stop-Service -Force
		echo "Отключение службы: $service"
		Get-Service -Name $service | Set-Service -StartupType Disabled
	}
	$ScheduledTaskList = @(
		# WindowsUpdate
		"Scheduled Start"
		# UpdateOrchestrator
		#"Schedule Scan"
		#"Schedule Scan Static Task"
	)
	Get-ScheduledTask -TaskName $ScheduledTaskList | Disable-ScheduledTask
	
}

# Удалить встроенные приложения из магазина Windows Store;
Function f_remove_builtinapps {
	# Get-AppxProvisionedPackage -Online | Select DisplayName, PackageName
	# Get-AppxPackage | Select Name, PackageFullName
	$apps = @(
		# Cortana
		"Microsoft.549981C3F5F10"
		# Техническая поддержка
		"Microsoft.GetHelp"
		# Советы Майкрософт
		"Microsoft.Getstarted"
		# Средство просмотра смешанной реальности
		"Microsoft.Microsoft3DViewer"
		# Office
		"Microsoft.MicrosoftOfficeHub"
		# Сбор классификации Майкрософт
		"Microsoft.MicrosoftSolitaireCollection"
		# Портал смешанной реальности
		"Microsoft.MixedReality.Portal"
		# Paint 3D
		"Microsoft.MSPaint"
		# OneNote для Windows 10
		"Microsoft.Office.OneNote"
		# Люди (Майкрософт)
		"Microsoft.People"
		# Skype
		"Microsoft.SkypeApp"
		# Фотографии (Майкрософт)
		"Microsoft.Windows.Photos"
		# Камера Windows
		"Microsoft.WindowsCamera"
		# Центр отзывов
		"Microsoft.WindowsFeedbackHub"
		# Карты Windows
		"Microsoft.WindowsMaps"
		# Взаимодействие xbox Live
		"Microsoft.Xbox.TCUI"
		# Компаньон консоли Xbox
		"Microsoft.XboxApp"
		# Подключаемый модуль Xbox
		"Microsoft.XboxGameOverlay"
		# Меню игры Xbox
		"Microsoft.XboxGamingOverlay"
		# Поставщик удостоверений Xbox
		"Microsoft.XboxIdentityProvider"
		# XboxSpeechToTextOverlay
		"Microsoft.XboxSpeechToTextOverlay"
		# Музыка Groove
		"Microsoft.ZuneMusic"
		# Кино и ТВ
		"Microsoft.ZuneVideo"
		# Яндекс.Музыка
		"A025C540.Yandex.Music"
	)
	ForEach ($app in $apps) {
		$ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq $app}
		if ($ProvisionedPackages -ne $null) {
			echo "Удаление подготовительного пакета: $app"
			ForEach  ($ProvisionedPackage in $ProvisionedPackages) {
				Remove-AppxProvisionedPackage -Online -PackageName $ProvisionedPackage.PackageName
			}
		}
		else {
			echo "Не удалось найти подготовительный пакет: $app"
		}
		$Packages = Get-AppxPackage | Where-Object {$_.Name -eq $app}
		if ($Packages -ne $null) {
			echo "Удаление пакета: $app"
			ForEach ($Package in $Packages) {
				Remove-AppxPackage -AllUsers -Package $Package.PackageFullName
			}
		}
		else {
			echo "Не удалось найти пакет: $app"
		}
	}
}

# Примеить Tweak's
Function f_tweaks {
	# Установить метод ввода по умолчанию на английский язык
	Set-WinDefaultInputMethodOverride "0409:00000409"
	# Отобразить "Этот компьютер" на рабочем столе (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Type DWord 0
	# Отобразить "Документы пользователя" на рабочем столе (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Type DWord 0
	# Открывать проводник для: "Этот компьютер" (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type DWord 1
	# Не показывать кнопку Кортаны на панели задач (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCortanaButton' -Type DWord 0
	# Не показывать недавно используемые папки на панели быстрого доступа (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowFrequent' -Type DWord 0
	# Не показывать недавно использовавшиеся файлы на панели быстрого доступа (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowRecent' -Type DWord 0
	# Не использовать автозапуск для всех носителей и устройств (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoplay' -Type DWord 1
	# Не разрешать приложениям на других устройствах запускать приложения и отправлять сообщения на этом устройстве и наоборот (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP' -Name 'RomeSdkChannelUserAuthzPolicy' -Type DWord 0
	# Включить планирование графического процессора с аппаратным ускорением
	Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'HwSchMode' -Type DWord 2
	# Отключить автоматическую установку рекомендованных приложений (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Type DWord 0
	# Не позволять веб-сайтам предоставлять местную информацию за счет доступа к списку языков (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Type DWord 1
	# Не предлагать персонализированные возможности, основанные на выбранном параметре диагностических данных (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Type DWord 0
	# Использовать кнопку PRINT SCREEN, чтобы запустить функцию создания фрагмента экрана (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\Control Panel\Keyboard' -Name 'PrintScreenKeyForSnippingEnabled' -Type DWord 1
	# Не получать советы, подсказки и рекомендации при использованию Windows (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Type DWord 0
	# Не показывать рекомендуемое содержимое в приложении "Параметры" (только для текущего пользователя)
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338393Enabled' -Type DWord 0
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-353694Enabled' -Type DWord 0
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-353696Enabled' -Type DWord 0
	# Заменить командную строку оболочкой Windows PowerShell
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'DontUsePowerShellOnWinX' -Type DWord 1
	# Скрыть папку "Объемные объекты" из "Этот компьютер" и из панели быстрого доступа (только для текущего пользователя)
	if (-not (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag')) {
		New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Force
	} Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String 'Hide'
	# Нe дoбaвлять "- яpлык" к имени coздaвaeмых яpлыков (только для текущего пользователя)
	if (-not (Test-Path -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates')) {
		New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates' -Force
	} Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates' -Name 'ShortcutNameTemplate' -Type String '%s.lnk'
	# Просмотр иконок Панели управления как: мелкие значки (только для текущего пользователя)
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
	} Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name 'AllItemsIconView' -Type DWord 1
	Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name 'PropertyType' -Type DWord 1
	# Изменить частоту формирования отзывов на "Никогда" для текущего пользователя
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules -Force
	} Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'NumberOfSIUFInPeriod' -Type DWord 0
	# Не разрешать приложениям использовать идентификатор рекламы (только для текущего пользователя)
	if (-not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Force
	} Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord 0
	# Не предлагать способы завершения настройки устройства для максимально эффективного использования Windows (только для текущего пользователя)
	if (-not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement)) {
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement -Force
	} Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement' -Name 'ScoobeSystemSettingEnabled' -Type DWord 0
	# Установить уровень сбора диагностических сведений ОС на "Минимальный"
	if (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -like "Enterprise*" -or $_.Edition -eq "Education"}) {
		# "Безопасность"
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord 0
		
	} else {
		# "Базовая настройка"
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord 1
	}
	# Отключить отчеты об ошибках Windows для текущего пользователя
	if ((Get-WindowsEdition -Online).Edition -notmatch "Core*") {
		Get-ScheduledTask -TaskName QueueReporting | Disable-ScheduledTask
		Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord 1
	}
}

# Оптимизация для систем установленных на SSD;
Function f_ssd_settings {
	# get-help Disable-ComputerRestore -examples
	# Отключаем защиту системы для дисков "C:\","D:\"
	Disable-ComputerRestore "C:\", "D:\"
	# Удалить все точки восстановления на всех дисках
	vssadmin delete shadows /all /quiet
	# Отключение файла подкачки
	wmic computersystem set AutomaticManagedPagefile=False
	wmic pagefileset delete
	# Отключение гибернации
	powercfg -h off
	# Отключение служб Superfetch и поиска Windows
	#Get-Service -Name SysMain | Stop-Service -Force
	#Get-Service -Name SysMain | Set-Service -StartupType Disabled
	Get-Service -Name WSearch | Stop-Service -Force
	Get-Service -Name WSearch | Set-Service -StartupType Disabled
	# Отключение Prefetch и Superfetch
	Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnablePrefetcher' -Type DWord 0
	Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnableSuperfetch' -Type DWord 0
	# Отключение ClearPageFileAtShutdown и LargeSystemCache
	Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Type DWord 0
	Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'LargeSystemCache' -Type DWord 0
}

# Удалить OneDrive;
function f_remove_onedrive
{
	[string]$UninstallString = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -ErrorAction Ignore | ForEach-Object -Process {$_.Meta.Attributes["UninstallString"]}
	if ($UninstallString)
	{
		Write-Verbose -Message $Localization.OneDriveUninstalling -Verbose
		Stop-Process -Name OneDrive -Force -ErrorAction Ignore
		Stop-Process -Name OneDriveSetup -Force -ErrorAction Ignore
		Stop-Process -Name FileCoAuth -Force -ErrorAction Ignore

		# Получаем ссылку на OneDriveSetup.exe и его аргумент(ы)
		[string[]]$OneDriveSetup = ($UninstallString -Replace("\s*/",",/")).Split(",").Trim()
		if ($OneDriveSetup.Count -eq 2)
		{
			Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..1] -Wait
		}
		else
		{
			Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..2] -Wait
		}

		# Получаем путь до папки пользователя OneDrive
		$OneDriveUserFolder = Get-ItemPropertyValue -Path HKCU:\Environment -Name OneDrive
		if ((Get-ChildItem -Path $OneDriveUserFolder | Measure-Object).Count -eq 0)
		{
			Remove-Item -Path $OneDriveUserFolder -Recurse -Force
		}
		else
		{
			$Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Localization.OneDriveNotEmptyFolder))
			Write-Error -Message $Message -ErrorAction SilentlyContinue
			Invoke-Item -Path $OneDriveUserFolder
		}

		Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive, OneDriveConsumer -Force -ErrorAction Ignore
		Remove-Item -Path HKCU:\SOFTWARE\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path $env:SystemDrive\OneDriveTemp -Recurse -Force -ErrorAction Ignore
		Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false

		# Получаем путь до папки OneDrive
		$OneDriveFolder = Split-Path -Path (Split-Path -Path $OneDriveSetup[0] -Parent)

		# Сохранить все открытые папки, чтобы восстановить их после перезапуска проводника
		Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
		$OpenedFolders = {(New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process {$_.Document.Folder.Self.Path}}.Invoke()

		# Завершить процесс проводника
		TASKKILL /F /IM explorer.exe

		# Попытка разрегистрировать FileSyncShell64.dll и удалить
		$FileSyncShell64dlls = Get-ChildItem -Path "$OneDriveFolder\*\amd64\FileSyncShell64.dll" -Force
		foreach ($FileSyncShell64dll in $FileSyncShell64dlls.FullName)
		{
			Start-Process -FilePath regsvr32.exe -ArgumentList "/u /s $FileSyncShell64dll" -Wait
			Remove-Item -Path $FileSyncShell64dll -Force -ErrorAction Ignore

			if (Test-Path -Path $FileSyncShell64dll)
			{
				$Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create($Localization.OneDriveFileSyncShell64dllBlocked))
				Write-Error -Message $Message -ErrorAction SilentlyContinue
			}
		}

		# Восстановляем закрытые папки
		Start-Process -FilePath explorer
		foreach ($OpenedFolder in $OpenedFolders)
		{
			if (Test-Path -Path $OpenedFolder)
			{
				Invoke-Item -Path $OpenedFolder
			}
		}

		Remove-Item -Path $OneDriveFolder -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path $env:LOCALAPPDATA\OneDrive -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path $env:LOCALAPPDATA\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
		Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction Ignore
	}
}

# Выполнить очистку папки WinSxS | Очистка и сжатие старых обновлений;
Function f_WinSxS {
	Dism.exe /Online /Cleanup-Image /StartComponentCleanup
}

# App Installer;
Function f_app_installer {
	$wingets = @(
		"7zip.7zip"
		"LibreOffice.LibreOffice"
		"Adobe.AdobeAcrobatReaderDC"
		"Google.Chrome"
		"VideoLAN.VLC"
		"Microsoft.VC++2005Redist-x64"
		"Microsoft.VC++2005Redist-x86"
		"Microsoft.VC++2008Redist-x64"
		"Microsoft.VC++2008Redist-x86"
		"Microsoft.VC++2010Redist-x64"
		"Microsoft.VC++2010Redist-x86"
		"Microsoft.VC++2012Redist-x64"
		"Microsoft.VC++2012Redist-x86"
		"Microsoft.VC++2013Redist-x64"
		"Microsoft.VC++2013Redist-x86"
		"Microsoft.VC++2015-2019Redist-x86"
		"Microsoft.VC++2015-2019Redist-x64"
	)
	ForEach ($winget in $wingets) {
		echo "Установка приложения: $winget"
		winget install $winget
	}
}

# Цикл главного меню;
do
{
	Show-Menu
	$input = Read-Host " - Выбор"
	switch ($input)
	{
		'1' {
			cls
			f_disable_services
		} '2' {
			cls
			f_disable_scheduledtasks
		} '3' {
			cls
			f_disable_components
		} '4' {
			cls
			f_disable_winupdate
		} '5' {
			cls
			f_remove_builtinapps
		} '6' {
			cls
			f_tweaks
		} '7' {
			cls
			f_ssd_settings
		}'8' {
			cls
			f_remove_onedrive
		}'9' {
			cls
			f_WinSxS
		}'10' {
			cls
			f_app_installer
		} 'q' {
			return
		}
	}
	pause
}
until ($input -eq 'q')
