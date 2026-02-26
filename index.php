<?php
require_once __DIR__ . '/vendor/autoload.php';

use Google\CloudFunctions\FunctionsFramework;
use Psr\Http\Message\ServerRequestInterface;

FunctionsFramework::http('smtpCheck', 'handler');

function handler(ServerRequestInterface $request): string
{
    $log = [];
    $success = false;
    $formData = [];

    if ($request->getMethod() === 'POST') {
        $formData = (array)$request->getParsedBody();
        
        try {
            $host = $formData['host'] ?? '';
            $port = $formData['port'] ?? 587;
            $user = $formData['user'] ?? '';
            $raw_pass = $formData['password'] ?? '';
            $mode = $formData['mode'] ?? 'smtp';
            $security = $formData['security'] ?? 'starttls';
            $from_email = $formData['from_email'] ?? '';
            $to_email = $formData['to_email'] ?? '';

            $final_pass = $raw_pass;

            // Logic convert IAM Key
            if ($mode === 'ses') {
                $log[] = ">>> MODE: AWS SES (IAM Keys)";
                try {
                    $final_pass = getSesSmtpPassword($raw_pass);
                    $log[] = "[+] IAM Key Conversion OK.";
                } catch (Exception $e) {
                    throw new Exception("Key Conversion Failed: " . $e->getMessage());
                }
            } else {
                $log[] = ">>> MODE: STANDARD SMTP";
            }

            runSmtpTest($host, $port, $user, $final_pass, $security, $from_email, $to_email, $log, $success);

        } catch (Exception $e) {
            $log[] = "[!] ERROR: " . $e->getMessage();
            $success = false;
        }
    }

    // Render HTML Output
    return renderHtml($formData, $log, $success);
}

// --- HELPER FUNCTIONS ---

function getSesSmtpPassword($secret) {
    $message = "SendRawEmail";
    $version = "\x02";
    $signature = hash_hmac('sha256', $message, $secret, true);
    return base64_encode($version . $signature);
}

function runSmtpTest($host, $port, $user, $pass, $security, $from, $to, &$log, &$success) {
    $timeout = 10;
    $protocol = ($security === 'ssl') ? 'ssl://' : 'tcp://';
    $connUri = $protocol . $host . ':' . $port;

    $log[] = "[*] Connecting to $connUri...";

    $errno = 0;
    $errstr = '';
    $socket = @stream_socket_client($connUri, $errno, $errstr, $timeout);

    if (!$socket) {
        throw new Exception("Connection failed: $errstr ($errno)");
    }

    $readResponse = function($sock) {
        $response = "";
        while($str = fgets($sock, 515)) {
            $response .= $str;
            if(substr($str, 3, 1) == " ") { break; }
        }
        return $response;
    };

    $sendCommand = function($sock, $cmd) {
        fputs($sock, $cmd . "\r\n");
    };

    // 1. Initial
    $readResponse($socket);

    // 2. EHLO
    $log[] = "[*] Sending EHLO...";
    $sendCommand($socket, "EHLO " . gethostname());
    $readResponse($socket);

    // 3. STARTTLS
    if ($security === 'starttls') {
        $log[] = "[*] Sending STARTTLS...";
        $sendCommand($socket, "STARTTLS");
        $res = $readResponse($socket);
        if (substr($res, 0, 3) != '220') {
            throw new Exception("STARTTLS failed: $res");
        }

        $log[] = "[*] Enabling Crypto...";
        if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
             throw new Exception("Failed to enable crypto/TLS.");
        }
        
        $sendCommand($socket, "EHLO " . gethostname());
        $readResponse($socket);
        $log[] = "[+] TLS Handshake OK.";
    }

    // 4. AUTH
    $log[] = "[*] Authenticating...";
    $sendCommand($socket, "AUTH LOGIN");
    $res = $readResponse($socket);
    if (substr($res, 0, 3) != '334') throw new Exception("AUTH LOGIN rejected: $res");

    $sendCommand($socket, base64_encode($user));
    $res = $readResponse($socket);
    if (substr($res, 0, 3) != '334') throw new Exception("Username rejected: $res");

    $sendCommand($socket, base64_encode($pass));
    $res = $readResponse($socket);
    if (substr($res, 0, 3) != '235') {
        if (strpos($host, 'amazonaws.com') !== false) {
             $log[] = "--> HINT: Check IAM Policy 'ses:SendRawEmail'.";
        }
        throw new Exception("Authentication Failed: $res");
    }
    $log[] = "[+] Authentication SUCCESS.";

    // 5. SEND
    $realSender = !empty($from) ? $from : $user;
    if (strpos($realSender, '@') === false) $realSender = $to;

    $log[] = "[*] Sending mail from <$realSender>...";
    $sendCommand($socket, "MAIL FROM: <$realSender>");
    $res = $readResponse($socket);
    if (substr($res, 0, 3) != '250') {
         if (strpos($host, 'amazonaws.com') !== false) {
             $log[] = "--> HINT: 'From' address must be verified in SES Sandbox.";
         }
         throw new Exception("MAIL FROM rejected: $res");
    }

    $sendCommand($socket, "RCPT TO: <$to>");
    $res = $readResponse($socket);
    if (substr($res, 0, 3) != '250') throw new Exception("RCPT TO rejected: $res");

    $sendCommand($socket, "DATA");
    $res = $readResponse($socket);
    if (substr($res, 0, 3) != '354') throw new Exception("DATA rejected: $res");

    $subject = "DevOps Tool: Cloud Run SMTP Test";
    $date = date(DATE_RFC2822);
    $body = "Date: $date\r\nFrom: $realSender\r\nTo: $to\r\nSubject: $subject\r\n\r\nSMTP Test via Google Cloud Run (PHP).\r\nHost: $host\r\n.\r\n";

    $sendCommand($socket, $body);
    $res = $readResponse($socket);
    if (substr($res, 0, 3) != '250') throw new Exception("Send Failed: $res");

    $log[] = "[+] Email Sent Successfully! ($res)";
    $sendCommand($socket, "QUIT");
    fclose($socket);
    $success = true;
}

function renderHtml($post, $log, $success) {
    // Escape output helper
    $e = function($v) { return htmlspecialchars($v ?? ''); };
    
    // Checkbox/Radio logic helpers
    $chkMode = function($val) use ($post) { 
        return (!isset($post['mode']) && $val == 'smtp') || (isset($post['mode']) && $post['mode'] == $val) ? 'checked' : ''; 
    };
    $chkSec = function($val) use ($post) {
        return (!isset($post['security']) && $val == 'starttls') || (isset($post['security']) && $post['security'] == $val) ? 'checked' : '';
    };

    $logHtml = '';
    if (!empty($log)) {
        $statusClass = $success ? 'bg-green-100 border-green-300 text-green-800' : 'bg-red-100 border-red-300 text-red-800';
        $statusText = $success ? 'SUCCESS' : 'FAILED';
        $logContent = implode("\n", array_map($e, $log));
        $logHtml = <<<HTML
        <div class="mt-8">
            <h2 class="font-bold mb-2 flex items-center">
                Log Output <span class="ml-2 px-2 py-0.5 text-xs rounded border {$statusClass}">{$statusText}</span>
            </h2>
            <div class="bg-gray-900 text-green-400 p-4 rounded text-xs font-mono overflow-auto h-64">
                <pre>{$logContent}</pre>
            </div>
        </div>
HTML;
    }

    return <<<HTML
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMTP Checker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen p-4 md:p-8">
    <div class="max-w-3xl mx-auto bg-white rounded-xl shadow-md overflow-hidden p-6">
        <div class="flex items-center justify-between border-b pb-4 mb-6">
            <h1 class="text-2xl font-bold text-gray-800">SMTP Checker</h1>
        </div>
        <form method="POST" class="space-y-6">
            <div class="bg-indigo-50 p-4 rounded-lg border border-indigo-100">
                <label class="block text-sm font-bold text-indigo-900 mb-3">1. Type</label>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <label class="flex items-start p-3 border border-indigo-200 rounded bg-white cursor-pointer">
                        <input type="radio" name="mode" value="smtp" onclick="switchMode('smtp')" {$chkMode('smtp')} class="mt-1 mr-3">
                        <div><span class="block text-sm font-bold">Standard SMTP</span></div>
                    </label>
                    <label class="flex items-start p-3 border border-indigo-200 rounded bg-white cursor-pointer">
                        <input type="radio" name="mode" value="ses" onclick="switchMode('ses')" {$chkMode('ses')} class="mt-1 mr-3">
                        <div><span class="block text-sm font-bold">AWS SES (IAM Keys)</span></div>
                    </label>
                </div>
                <div id="ses_region_box" class="mt-3 hidden">
                    <select id="ses_region" onchange="applySesRegion()" class="w-full text-sm border-gray-300 rounded p-1">
                        <option value="">-- Select SES Region --</option>
                        <option value="us-east-1">US East (N. Virginia)</option>
                        <option value="us-west-2">US West (Oregon)</option>
                        <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                    </select>
                </div>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-12 gap-4">
                <div class="md:col-span-8">
                    <label class="block text-sm font-medium text-gray-700">SMTP Host</label>
                    <input type="text" name="host" id="host" value="{$e($post['host'] ?? '')}" required class="mt-1 w-full border rounded p-2">
                </div>
                <div class="md:col-span-4">
                    <label class="block text-sm font-medium text-gray-700">Port</label>
                    <input type="number" name="port" id="port" value="{$e($post['port'] ?? '587')}" required class="mt-1 w-full border rounded p-2">
                </div>
            </div>
            <div class="flex space-x-6 text-sm">
                <label class="inline-flex items-center"><input type="radio" name="security" value="starttls" onclick="setPort(587)" {$chkSec('starttls')} class="mr-2"> StartTLS (587)</label>
                <label class="inline-flex items-center"><input type="radio" name="security" value="ssl" onclick="setPort(465)" {$chkSec('ssl')} class="mr-2"> SSL/TLS (465)</label>
                <label class="inline-flex items-center"><input type="radio" name="security" value="none" onclick="setPort(25)" {$chkSec('none')} class="mr-2"> None (25)</label>
            </div>
            <div class="border-t pt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label id="lbl_user" class="block text-sm font-medium text-gray-700">Username</label>
                    <input type="text" name="user" value="{$e($post['user'] ?? '')}" required class="mt-1 w-full border rounded p-2 font-mono text-sm">
                </div>
                <div>
                    <label id="lbl_pass" class="block text-sm font-medium text-gray-700">Password</label>
                    <input type="password" name="password" value="{$e($post['password'] ?? '')}" required class="mt-1 w-full border rounded p-2 font-mono text-sm">
                </div>
            </div>
            <div class="border-t pt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700">Sender (From)</label>
                    <input type="email" name="from_email" value="{$e($post['from_email'] ?? '')}" class="mt-1 w-full border rounded p-2">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700">Recipient (To)</label>
                    <input type="email" name="to_email" value="{$e($post['to_email'] ?? '')}" required class="mt-1 w-full border rounded p-2">
                </div>
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white font-bold py-3 rounded hover:bg-blue-700 transition">RUN TEST</button>
        </form>
        {$logHtml}
    </div>
    <script>
        const els = {
            host: document.getElementById('host'),
            port: document.getElementById('port'),
            lblUser: document.getElementById('lbl_user'),
            lblPass: document.getElementById('lbl_pass'),
            sesBox: document.getElementById('ses_region_box'),
            sesRegion: document.getElementById('ses_region')
        };
        function switchMode(mode) {
            if (mode === 'ses') {
                els.lblUser.innerText = "AWS Access Key ID";
                els.lblPass.innerText = "AWS Secret Access Key";
                els.sesBox.classList.remove('hidden');
            } else {
                els.lblUser.innerText = "Username / Email";
                els.lblPass.innerText = "Password / App Password";
                els.sesBox.classList.add('hidden');
            }
        }
        function applySesRegion() {
            const r = els.sesRegion.value;
            if(!r) return;
            els.host.value = `email-smtp.\${r}.amazonaws.com`;
            els.port.value = 587;
            document.querySelector('input[value="starttls"]').checked = true;
        }
        function setPort(p) { els.port.value = p; }
        document.addEventListener('DOMContentLoaded', () => {
            const mode = document.querySelector('input[name="mode"]:checked');
            if(mode) switchMode(mode.value);
        });
    </script>
</body>
</html>
HTML;
}
?>
