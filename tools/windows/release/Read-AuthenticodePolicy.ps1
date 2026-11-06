# Shared provisioning preflight. AdapterCustody separately holds the reviewed
# entry bytes; policy decoding itself never invokes an adapter.
function Read-AuthenticodePolicy {
  param(
    [Parameter(Mandatory)][string]$Policy,
    [ValidatePattern('\A[a-fA-F0-9]{64}\z')][string]$ExpectedSha256,
    [ref]$RawSha256
  )

  $stream = [IO.File]::Open($Policy, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    if ($stream.Length -gt 65536) { throw 'Authenticode policy is oversized' }
    $bytes = [byte[]]::new([int]$stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($read -eq 0) { throw 'Authenticode policy changed during read' }
      $offset += $read
    }
    if ($stream.ReadByte() -ne -1) { throw 'Authenticode policy changed during read' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    # Bind every later original/staged policy read to this first raw byte
    # sequence before JSON decoding or any verifier/trust API can be invoked.
    if ($ExpectedSha256 -and $digest -cne $ExpectedSha256.ToLowerInvariant()) {
      throw 'Authenticode policy raw SHA-256 differs from the first validated policy'
    }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
  } finally { $stream.Dispose() }

  # ConvertFrom-Json supplies JSON decoding, including escaped key names. The
  # anchored lexical grammar separately limits this v2 policy to one flat
  # object of strings/nulls and retains every key occurrence: the decoder alone
  # can silently replace duplicate properties on Windows PowerShell 5.1.
  $policyData = $raw | ConvertFrom-Json -ErrorAction Stop
  $jsonString = '"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
  $ws = '[ \t\r\n]*'
  $member = '(?<key>' + $jsonString + ')' + $ws + ':' + $ws + '(?<value>' + $jsonString + '|null)'
  $regexOptions = [Text.RegularExpressions.RegexOptions]::CultureInvariant
  $regexTimeout = [TimeSpan]::FromSeconds(1)
  try {
    $shape = [regex]::Match($raw, '\A' + $ws + '\{' + $ws + '(?:' + $member + '(?:' + $ws + ',' + $ws + $member + ')*)?' + $ws + '\}' + $ws + '\z', $regexOptions, $regexTimeout)
  } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
    throw 'Authenticode policy flat-object parsing exceeded its bounded regex budget'
  }
  $expected = @('schema', 'publisher_certificate_sha256', 'timestamp_protocol',
    'timestamp_attribute_oid', 'rfc3161_structural_verifier',
    'provider_attestation_verifier', 'wintun_sha256', 'authenticode_provider_sha256',
    'rfc3161_structural_verifier_sha256', 'provider_attestation_verifier_sha256')
  if (-not $shape.Success -or $shape.Groups['key'].Captures.Count -ne $expected.Count) {
    throw 'Authenticode policy must contain exactly the ten flat v2 fields'
  }
  foreach ($token in @($shape.Groups['key'].Captures) + @($shape.Groups['value'].Captures)) {
    # Check the original escapes too: some JSON decoder versions replace an
    # unpaired escaped surrogate before exposing the decoded string.
    try {
      $escapes = [regex]::Matches($token.Value, '\\(?:u(?<hex>[0-9a-fA-F]{4})|["\\/bfnrt])', $regexOptions, $regexTimeout)
      # MatchCollection evaluates lazily: force completion inside this guard.
      $escapeCount = $escapes.Count
    } catch [Text.RegularExpressions.RegexMatchTimeoutException] {
      throw 'Authenticode policy Unicode parsing exceeded its bounded regex budget'
    }
    for ($i = 0; $i -lt $escapeCount; $i++) {
      if (-not $escapes[$i].Groups['hex'].Success) { continue }
      $point = [Convert]::ToInt32($escapes[$i].Groups['hex'].Value, 16)
      if ($point -ge 0xd800 -and $point -le 0xdbff) {
        if ($i + 1 -ge $escapes.Count -or
            $escapes[$i + 1].Index -ne $escapes[$i].Index + $escapes[$i].Length -or
            -not $escapes[$i + 1].Groups['hex'].Success) {
          throw 'Authenticode policy has an unpaired Unicode escape'
        }
        $low = [Convert]::ToInt32($escapes[$i + 1].Groups['hex'].Value, 16)
        if ($low -lt 0xdc00 -or $low -gt 0xdfff) { throw 'Authenticode policy has an unpaired Unicode escape' }
        $i++
      } elseif ($point -ge 0xdc00 -and $point -le 0xdfff) {
        throw 'Authenticode policy has an unpaired Unicode escape'
      }
    }
  }
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($token in $shape.Groups['key'].Captures) {
    $decoded = ('{' + $token.Value + ':null}') | ConvertFrom-Json -ErrorAction Stop
    $names = @($decoded.PSObject.Properties.Name)
    if ($names.Count -ne 1 -or $expected -cnotcontains $names[0] -or -not $seen.Add($names[0])) {
      throw 'Authenticode policy contains duplicate or unexpected JSON keys'
    }
  }
  if (@($policyData.PSObject.Properties).Count -ne $expected.Count) {
    throw 'Authenticode policy has an unexpected object schema'
  }
  foreach ($name in $expected) {
    $value = $policyData.PSObject.Properties[$name].Value
    if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
      throw "Authenticode policy field is unprovisioned or not a string: $name"
    }
    # Reject unpaired Unicode surrogates rather than allowing decoder-specific
    # path/name replacement. Valid Unicode adapter paths remain supported.
    for ($i = 0; $i -lt $value.Length; $i++) {
      if ([char]::IsHighSurrogate($value[$i])) {
        if ($i + 1 -ge $value.Length -or -not [char]::IsLowSurrogate($value[$i + 1])) {
          throw "Authenticode policy field has invalid Unicode: $name"
        }
        $i++
      } elseif ([char]::IsLowSurrogate($value[$i])) {
        throw "Authenticode policy field has invalid Unicode: $name"
      }
    }
  }
  if ($policyData.schema -cne 'aegis_windows_authenticode_policy_v2' -or
      $policyData.publisher_certificate_sha256 -cnotmatch '\A[a-fA-F0-9]{64}\z' -or
      $policyData.authenticode_provider_sha256 -cnotmatch '\A[a-fA-F0-9]{64}\z' -or
      $policyData.rfc3161_structural_verifier_sha256 -cnotmatch '\A[a-fA-F0-9]{64}\z' -or
      $policyData.provider_attestation_verifier_sha256 -cnotmatch '\A[a-fA-F0-9]{64}\z' -or
      $policyData.timestamp_protocol -cne 'rfc3161' -or
      $policyData.timestamp_attribute_oid -cne '1.3.6.1.4.1.311.3.3.1' -or
      $policyData.wintun_sha256 -cne 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce' -or
      -not (Test-Path -LiteralPath $policyData.rfc3161_structural_verifier -PathType Leaf) -or
      -not (Test-Path -LiteralPath $policyData.provider_attestation_verifier -PathType Leaf)) {
    throw 'Authenticode policy lacks the reviewed publisher pin, RFC3161 verifier, or provider attestation verifier'
  }
  $policyData.publisher_certificate_sha256 = $policyData.publisher_certificate_sha256.ToLowerInvariant()
  if ($null -ne $RawSha256) { $RawSha256.Value = $digest }
  return $policyData
}
