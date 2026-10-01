# Keep Windows from idle-sleeping while a WSL benchmark runs (like `caffeinate`).
# ES_CONTINUOUS | ES_SYSTEM_REQUIRED; released automatically when this process exits.
# Does not prevent sleep on lid close or manual sleep.
$sig = '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
$api = Add-Type -MemberDefinition $sig -Name Power -Namespace KNighter -PassThru
while ($true) {
    [void]$api::SetThreadExecutionState([uint32]"0x80000001")
    Start-Sleep -Seconds 60
}
