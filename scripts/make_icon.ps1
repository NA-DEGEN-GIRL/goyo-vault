# Renders assets/goyo.ico (PNG frames) and assets/icon-256.png.
# Usage: powershell -NoProfile -File scripts/make_icon.ps1
Add-Type -AssemblyName System.Drawing
$root = Split-Path -Parent $PSScriptRoot
$assets = Join-Path $root 'assets'
New-Item -ItemType Directory -Force $assets | Out-Null

function RoundedPath([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

# Drawn on a 256 grid and scaled, with thicker strokes at small sizes.
function Render([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 256.0
    $g.ScaleTransform($s, $s)

    $margin = if ($size -le 24) { 4 } else { 10 }
    $tile = RoundedPath $margin $margin (256 - 2 * $margin) (256 - 2 * $margin) 58
    $top = [System.Drawing.Color]::FromArgb(255, 58, 58, 64)
    $bottom = [System.Drawing.Color]::FromArgb(255, 20, 20, 23)
    $rect = New-Object System.Drawing.RectangleF 0, 0, 256, 256
    $fill = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, $top, $bottom, 90.0
    $g.FillPath($fill, $tile)
    if ($size -ge 32) {
        $edge = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(40, 255, 255, 255)), 3
        $g.DrawPath($edge, $tile)
    }

    $ink = [System.Drawing.Color]::FromArgb(255, 244, 244, 245)
    $stroke = [Math]::Max(22.0, 2.4 / $s)
    $pen = New-Object System.Drawing.Pen $ink, $stroke
    $pen.StartCap = 'Round'
    $pen.EndCap = 'Round'
    # Shackle: a half ring with straight legs into the body.
    $g.DrawArc($pen, 86, 56, 84, 84, 180, 180)
    $g.DrawLine($pen, 86, 98, 86, 124)
    $g.DrawLine($pen, 170, 98, 170, 124)
    $body = RoundedPath 62 118 132 96 22
    $g.FillPath((New-Object System.Drawing.SolidBrush $ink), $body)
    if ($size -ge 24) {
        $hole = New-Object System.Drawing.SolidBrush $bottom
        $g.FillEllipse($hole, 115, 146, 26, 26)
        $slot = RoundedPath 122 160 12 30 5
        $g.FillPath($hole, $slot)
    }
    $g.Dispose()
    return $bmp
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$frames = @()
foreach ($size in $sizes) {
    $bmp = Render $size
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    if ($size -eq 256) { $bmp.Save((Join-Path $assets 'icon-256.png'), [System.Drawing.Imaging.ImageFormat]::Png) }
    $bmp.Dispose()
    $frames += , @($size, $ms.ToArray())
}

# ICO container with PNG-compressed frames (Windows Vista and later).
$out = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter $out
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$frames.Count)
$offset = 6 + 16 * $frames.Count
foreach ($f in $frames) {
    $dim = if ($f[0] -ge 256) { 0 } else { $f[0] }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32)
    $w.Write([UInt32]$f[1].Length); $w.Write([UInt32]$offset)
    $offset += $f[1].Length
}
foreach ($f in $frames) { $w.Write([byte[]]$f[1]) }
$w.Flush()
[System.IO.File]::WriteAllBytes((Join-Path $assets 'goyo.ico'), $out.ToArray())
"Wrote assets/goyo.ico ($($frames.Count) frames) and assets/icon-256.png"
