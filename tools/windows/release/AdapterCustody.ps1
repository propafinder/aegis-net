# Entry-file custody only: an adapter's modules, child tools and remote service
# are separate provisioning trust inputs, not sealed by this read handle.
function Initialize-AdapterCustody {
  if ($env:OS -cne 'Windows_NT') { throw 'Pinned Authenticode adapters require Windows file sharing semantics' }
  if ('Aegis.Release.AdapterLease' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace Aegis.Release {
  public sealed class AdapterLease : IDisposable {
    [StructLayout(LayoutKind.Sequential)]
    private struct Info {
      public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh;
      public uint WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
      IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    private const uint Reparse=0x400, Directory=0x10, OpenReparse=0x200000, Backup=0x2000000;
    private const long Limit=256L*1024*1024;
    private readonly List<SafeFileHandle> directories = new List<SafeFileHandle>();
    private readonly List<string> directoryPaths = new List<string>();
    private readonly List<Info> directoryIdentities = new List<Info>();
    private FileStream file;
    private Info original;
    private string pin;
    public string Path { get; private set; }
    private AdapterLease() {}
    private static bool Same(Info a, Info b, bool directory) {
      return a.Volume==b.Volume && a.IndexHigh==b.IndexHigh && a.IndexLow==b.IndexLow &&
        a.Attributes==b.Attributes && (directory || (a.Links==b.Links && a.SizeHigh==b.SizeHigh &&
        a.SizeLow==b.SizeLow && a.WriteHigh==b.WriteHigh && a.WriteLow==b.WriteLow));
    }
    private static Info Identity(SafeFileHandle handle, bool directory) {
      Info info;
      if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
      if ((info.Attributes & Reparse)!=0 || ((info.Attributes & Directory)!=0)!=directory ||
          (!directory && info.Links!=1)) throw new IOException("Adapter file/link identity rejected");
      return info;
    }
    private static string NamedPath(SafeFileHandle handle) {
      StringBuilder name = new StringBuilder(32768);
      uint count=GetFinalPathNameByHandleW(handle, name, (uint)name.Capacity, 0);
      if (count==0 || count>=name.Capacity) throw new IOException("Adapter canonical handle path unavailable");
      string path=name.ToString();
      if (!path.StartsWith(@"\\?\", StringComparison.Ordinal)) throw new IOException("Adapter must use a local drive path");
      return path.Substring(4);
    }
    private static SafeFileHandle Open(string path, bool directory) {
      // Directory WRITE sharing allows unrelated child creation; omitting
      // DELETE sharing prevents renaming/deleting the bound path ancestry.
      // Include LIST_DIRECTORY, not attribute-only access: sharing restrictions
      // must apply to an ordinary data-read handle for each ancestor.
      SafeFileHandle handle=CreateFileW(path, directory ? 0x81u : 0x80000000u,
        directory ? 3u : 1u, IntPtr.Zero, 3, OpenReparse | (directory ? Backup : 0), IntPtr.Zero);
      if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
      try {
        Identity(handle, directory);
        if (!String.Equals(NamedPath(handle), path, StringComparison.Ordinal))
          throw new IOException("Adapter path is not its exact canonical handle path");
        return handle;
      } catch { handle.Dispose(); throw; }
    }
    public static AdapterLease Acquire(string path, string expectedSha256) {
      if (String.IsNullOrEmpty(path) || path.Length<3 || !((path[0]>='A' && path[0]<='Z') || (path[0]>='a' && path[0]<='z')) || path[1]!=':' || path[2]!='\\' ||
          path.IndexOf('/')>=0 || path.IndexOf(':', 2)>=0 || !String.Equals(System.IO.Path.GetFullPath(path), path, StringComparison.Ordinal))
        throw new IOException("Adapter path must be an exact absolute local drive path");
      string extension=System.IO.Path.GetExtension(path);
      if (!String.Equals(extension, ".ps1", StringComparison.OrdinalIgnoreCase) &&
          !String.Equals(extension, ".exe", StringComparison.OrdinalIgnoreCase))
        throw new IOException("Adapter entry must be a PowerShell script or executable");
      if (expectedSha256==null || expectedSha256.Length!=64) throw new IOException("Adapter SHA-256 is unprovisioned");
      foreach (char c in expectedSha256) if (!Uri.IsHexDigit(c)) throw new IOException("Adapter SHA-256 is invalid");
      AdapterLease lease=new AdapterLease();
      lease.Path=path; lease.pin=expectedSha256.ToLowerInvariant();
      try {
        List<string> parents=new List<string>();
        for (string parent=System.IO.Path.GetDirectoryName(path); !String.IsNullOrEmpty(parent); parent=System.IO.Path.GetDirectoryName(parent))
          parents.Add(parent);
        parents.Reverse();
        foreach (string parent in parents) {
          SafeFileHandle handle=Open(parent, true);
          lease.directories.Add(handle); lease.directoryPaths.Add(parent);
          lease.directoryIdentities.Add(Identity(handle, true));
        }
        SafeFileHandle entry=Open(path, false);
        try { lease.file=new FileStream(entry, FileAccess.Read, 4096, false); }
        catch { entry.Dispose(); throw; }
        lease.original=Identity(lease.file.SafeFileHandle, false);
        lease.Verify();
        return lease;
      } catch { lease.Dispose(); throw; }
    }
    public void Verify() {
      if (file==null) throw new ObjectDisposedException("AdapterLease");
      for (int i=0; i<directories.Count; i++) {
        if (!Same(directoryIdentities[i], Identity(directories[i], true), true) ||
            !String.Equals(NamedPath(directories[i]), directoryPaths[i], StringComparison.Ordinal))
          throw new IOException("Adapter ancestry changed");
      }
      if (!Same(original, Identity(file.SafeFileHandle, false), false) || file.Length>Limit ||
          !String.Equals(NamedPath(file.SafeFileHandle), Path, StringComparison.Ordinal))
        throw new IOException("Adapter held file changed or is oversized");
      string digest;
      file.Position=0;
      using (SHA256 hash=SHA256.Create()) digest=BitConverter.ToString(hash.ComputeHash(file)).Replace("-", "").ToLowerInvariant();
      if (!String.Equals(digest, pin, StringComparison.Ordinal) || !Same(original, Identity(file.SafeFileHandle, false), false))
        throw new IOException("Adapter held SHA-256/identity mismatch");
      using (SafeFileHandle named=Open(Path, false)) {
        if (!Same(original, Identity(named, false), false)) throw new IOException("Adapter named generation changed");
      }
    }
    public void Dispose() {
      if (file!=null) { file.Dispose(); file=null; }
      for (int i=directories.Count-1; i>=0; i--) directories[i].Dispose();
      directories.Clear();
    }
  }
}
'@
}

function Open-AuthenticodeAdapters {
  param([Parameter(Mandatory)]$PolicyData, [string]$ProviderPath)
  Initialize-AdapterCustody
  $leases = [ordered]@{}
  try {
    $leases.Structural = [Aegis.Release.AdapterLease]::Acquire($PolicyData.rfc3161_structural_verifier, $PolicyData.rfc3161_structural_verifier_sha256)
    $leases.Attestation = [Aegis.Release.AdapterLease]::Acquire($PolicyData.provider_attestation_verifier, $PolicyData.provider_attestation_verifier_sha256)
    if ($ProviderPath) { $leases.Provider = [Aegis.Release.AdapterLease]::Acquire($ProviderPath, $PolicyData.authenticode_provider_sha256) }
    return $leases
  } catch {
    foreach ($lease in $leases.Values) { $lease.Dispose() }
    throw
  }
}

function Assert-AuthenticodeAdaptersCurrent($Leases) {
  foreach ($lease in $Leases.Values) { $lease.Verify() }
}

function Close-AuthenticodeAdapters($Leases) {
  foreach ($lease in $Leases.Values) { $lease.Dispose() }
}

function Invoke-PinnedAdapter {
  param([Parameter(Mandatory)]$Lease, [Parameter(Mandatory)][System.Collections.IDictionary]$Parameters)
  $Lease.Verify()
  $failure = $null
  $outputs = [Collections.Generic.List[string]]::new()
  $retention = [PSCustomObject]@{ Bytes = 0 }
  try {
    $global:LASTEXITCODE = 0
    $entry = $Lease.Path
    $retain = {
      $text = [string]$_
      $retention.Bytes += [Text.Encoding]::UTF8.GetByteCount($text)
      if ($retention.Bytes -gt 16MB) { throw 'Adapter stdout exceeded its retention bound' }
      $outputs.Add($text)
    }
    if ([IO.Path]::GetExtension($entry) -ieq '.ps1') {
      & $entry @Parameters | ForEach-Object $retain
    } else {
      $argv = @()
      foreach ($key in $Parameters.Keys) {
        if ($key -cnotmatch '\A[A-Za-z][A-Za-z0-9]*\z') { throw 'Invalid adapter parameter name' }
        if ($Parameters[$key] -is [bool]) { if ($Parameters[$key]) { $argv += "-$key" } }
        else { $argv += "-$key"; $argv += [string]$Parameters[$key] }
      }
      & $entry @argv | ForEach-Object $retain
    }
    $succeeded = $?
    $exitCode = $global:LASTEXITCODE
    if (-not $succeeded -or $exitCode -ne 0) { throw 'Pinned adapter returned failure' }
  } catch { $failure = $_ }
  try { $Lease.Verify() } catch { if ($null -eq $failure) { $failure = $_ } }
  if ($null -ne $failure) { throw $failure }
  # No adapter stdout is returned to a promoting caller before exit/custody.
  $outputs.ToArray()
}
